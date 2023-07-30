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
    argss, _ := ccmd.Flags().GetString("args")
    if program=="pid-matcher" {
     command := exec.Command("./pid-matcher/./pidmatcher","-pid",argss)
     command.Stdout = os.Stdout
     err := command.Run()
     if err != nil {
         log.Println("Enter pid to be matched using -a")
     }
    } else if program=="tcp-connect" {
        command:= exec.Command("./tcp-connect/./tcp_connect")
        command.Stdout = os.Stdout
        err := command.Run()
        if err != nil {
        log.Println(err)
        }
    } else if program=="cgroup-counter" {
        command:= exec.Command("./cgroup-counter/./cgroup-counter")
        command.Stderr = os.Stderr
        err := command.Run()
        if err != nil {
        log.Println(err)
        }
    } else {
        log.Println("Enter a program to be run")
    }

}

func init() {
    	rootCmd.AddCommand(runCmd)
    	runCmd.Flags().StringP("program", "p", "", "Select program to be run")
    	runCmd.Flags().StringP("args", "a", "", "Add arguments necessary for the given program")
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
