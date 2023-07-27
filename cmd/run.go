package cmd
import (
    "os"
    "log"
	"github.com/spf13/cobra"
    "os/exec"
)
var (
	runCmd = &cobra.Command{
		Use:   "run",
		Short: "Run any program type. Mention the -p flag to select program to be",
		Long:  ``,
		Run: run,
	}
)

func run(ccmd *cobra.Command, args []string) {
    
    program, _ := ccmd.Flags().GetString("program")
    if program=="pid_matcher" {
 	command:= exec.Command("./pid_matcher/./pidmatcher")
     command.Stdout = os.Stdout
     err := command.Run()
     if err != nil {
         log.Println(err)
     }
        /*    command:= exec.Command("./pid_matcher/./pidmatcher",cmd)
	        // set var to get the output
    var out bytes.Buffer

     // set the output to our variable
     command.Stdout = &out
     err := command.Run()
     if err != nil {
         log.Println(err)
     }

    fmt.Println(out.String())
        //if err != nil {
		//panic(err)
	   // }
        //fmt.Printf("%s", res)
    */
    } else if program=="tcp_connect" {
   command:= exec.Command("./bpf_core_read/./tcp_connect")
     command.Stdout = os.Stdout
     err := command.Run()
     if err != nil {
         log.Println(err)
     }
    }
}

func init() {
    	rootCmd.AddCommand(runCmd)
    	runCmd.Flags().StringP("program", "p", "", "Select program to be run")
    }
