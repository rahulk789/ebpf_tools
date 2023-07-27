package cmd
import (
	"fmt"
	"github.com/spf13/cobra"
)
var (
	testCmd = &cobra.Command{
		Use:   "list",
		Short: "List all available programs for execution",
		Long:  ``,
		Run: list,
	}
)

func list(ccmd *cobra.Command, args []string) {
    fmt.Println("tcp-connect\npid-matcher\n")
}
func init() {
    	rootCmd.AddCommand(testCmd)
    }
