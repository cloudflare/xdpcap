package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/pkg/errors"
)

type flags struct {
	*flag.FlagSet

	mapPath  string
	pcapFile *os.File

	quiet bool
	flush bool

	filterExpr string
	filterOpts filterOpts
}

// parseFlags creates the flags, and attempts to parse args.
// On error, the returned flags is fully setup, but will not hold values for all the arguments.
func parseFlags(name string, args []string) (flags, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	// flag insists on always printing things out in the case of errors, disable that
	fs.SetOutput(ioutil.Discard)

	flags := flags{
		FlagSet: fs,
	}

	flags.UintVar(&flags.filterOpts.perfPerCPUBuffer, "buffer", 8192, "Per CPU perf buffer size to create (`bytes`)")
	flags.UintVar(&flags.filterOpts.perfWatermark, "watermark", 4096, "Perf watermark (`bytes`)")
	flags.BoolVar(&flags.quiet, "q", false, "Don't print statistics")
	flags.BoolVar(&flags.flush, "flush", false, "Flush pcap data written to <output> for every packet received")

	err := flags.Parse(args)
	if err != nil {
		return flags, err
	}

	if flags.NArg() < 2 {
		return flags, errors.New("missing required <debug map> / <output>")
	}

	flags.mapPath = flags.Arg(0)

	if output := flags.Arg(1); output == "-" {
		flags.pcapFile = os.Stdout
		flags.quiet = true
		flags.flush = true
	} else {
		var err error
		flags.pcapFile, err = os.Create(output)
		if err != nil {
			return flags, errors.Wrap(err, "creating output")
		}
	}

	// Default filter is match anything
	if flags.NArg() >= 3 {
		flags.filterExpr = strings.Join(flags.Args()[2:], " ")
	}

	return flags, nil
}

func (flags flags) Usage() string {
	usage := strings.Builder{}

	usage.WriteString(fmt.Sprintf(
		`%s [options] <debug map> <output> [<tcpdump filter expr>]

Capture packets from XDP programs matching a tcpdump filter expression.

<output> may be "-" to write to stdout. Implies -q and -flush.

`, flags.Name()))

	// temporarily re-enable printing to get the default usage
	flags.SetOutput(&usage)
	flags.PrintDefaults()
	flags.SetOutput(ioutil.Discard)

	return usage.String()
}
