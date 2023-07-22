package cmd
import (
	"fmt"
    "github.com/rahulk789/ebpf_tools/cmd"
	"github.com/spf13/cobra"
)
var (
	testCmd = &cobra.Command{
		Use:   "test",
		Short: "List all available programs for execution",
		Long:  ``,
		Run: test,
	}
)

func test(ccmd *cobra.Command, args []string) {
    fmt.Println("this is pidmatcher")
}
func init() {
    	cmd.rootCmd.AddCommand(testCmd)
    }
