package main

// Opt-in synthetic cost experiments. No protected inputs, masks or outputs
// are printed. A full 10,000 x 50 circuit is intentionally not allocated.
import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPrimitiveVMeasuredCosts(t *testing.T) {
	if os.Getenv("PRIMITIVE_V_BENCH") != "1" {
		t.Skip("opt-in synthetic benchmark")
	}
	for _, op := range []string{"add", "mulq64", "exp", "expnegative", "log", "rounddiv_positive", "dot10"} {
		t.Run(op, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("package main\n" + primitiveVNumericSource())
			n := 1
			if op == "dot10" {
				n = 10
			} else if op == "rounddiv_positive" {
				n = 2
			}
			fmt.Fprintf(&source, "func main(g [%d]int192, e [%d]int192) [1]int192 {\nvar out [1]int192\nx := g[0]+e[0]\n", n+1, n)
			switch op {
			case "add":
				source.WriteString("y := x+int192(1)\n")
			case "mulq64":
				source.WriteString("y := primitiveVMulQ64(x,x)\n")
			case "exp":
				source.WriteString("y := primitiveVExpQ64(x)\n")
			case "expnegative":
				source.WriteString("y := primitiveVExpNegativeQ64(-x)\n")
			case "log":
				source.WriteString("y := primitiveVLogQ64(x)\n")
			case "rounddiv_positive":
				source.WriteString("y := primitiveVRoundDiv(x,g[1]+e[1])\n")
			case "dot10":
				// beta=RN(0.1*2^50); f50 features summed at f100,
				// then one nearest-even division by 2^36 to q64.
				source.WriteString("sum := x*int192(112589990684262)\n")
				for i := 1; i < 10; i++ {
					fmt.Fprintf(&source, "sum = sum+(g[%d]+e[%d])*int192(112589990684262)\n", i, i)
				}
				source.WriteString("y := primitiveVRoundDiv(sum,int192(68719476736))\n")
			}
			fmt.Fprintf(&source, "out[0]=y-g[%d]\nreturn out\n}\n", n)
			started := time.Now()
			p, err := primitiveVCompile(source.String(), 192, n+1, n, 1)
			if err != nil {
				t.Fatal(err)
			}
			compileTime := time.Since(started)
			g, e := make([]*big.Int, n), make([]*big.Int, n)
			for i := range g {
				g[i] = new(big.Int).Set(primitiveVScale)
				e[i] = new(big.Int)
			}
			if op == "dot10" {
				for i := range g {
					g[i].Rsh(g[i], 14)
				}
			}
			started = time.Now()
			_, bytes := primitiveVTestProtocol(t, p, g, e)
			protocolTime := time.Since(started)
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			record := map[string]interface{}{"operation": op, "goos": runtime.GOOS, "goarch": runtime.GOARCH, "go": runtime.Version(), "compile_seconds": compileTime.Seconds(), "protocol_seconds": protocolTime.Seconds(), "gates": p.Circuit.NumGates, "wires": p.Circuit.NumWires, "nonxor_gates": p.Circuit.Stats.NumNonXOR(), "table_bytes": primitiveVTableBytes(p.Circuit), "garbler_wire_bytes": bytes, "heap_sys_bytes": mem.HeapSys}
			encoded, _ := json.Marshal(record)
			t.Log(string(encoded))
		})
	}
}

func BenchmarkPrimitiveVRoute10000(b *testing.B) {
	perm := make([]int, 10000)
	for i := range perm {
		perm[i] = len(perm) - 1 - i
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := primitiveVPermutationControls(perm); err != nil {
			b.Fatal(err)
		}
	}
}
