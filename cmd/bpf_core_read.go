package cmd
import (
	"fmt"
	"github.com/spf13/cobra"
)
var (
	listCmd = &cobra.Command{
		Use:   "list",
		Short: "List all available program tools !!",
		Long:  ``,
		Run: list,
	}
)

func list(ccmd *cobra.Command, args []string) {
		fmt.Println("hello world")
}

func init() {
    	rootCmd.AddCommand(listCmd)
    }
