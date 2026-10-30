package output

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/XORRav/wraithflag/hunter"
)

func PrintJSON(results []hunter.Result) {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshaling JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}
