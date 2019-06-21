package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"time"

	"github.com/runletapp/crabfs"
	crabfsCrypto "github.com/runletapp/crabfs/crypto"
	crabfsOpts "github.com/runletapp/crabfs/options"
)

func usage() {
	fmt.Printf("Crabfs cp: Usage\n")
	fmt.Printf("----------------\n")
	fmt.Printf("%s ./privkey.key crabfs://bucket/filename ./local_file.ext\n", os.Args[0])
	fmt.Printf("%s ./privkey.key ./local_file.ext crabfs://bucket/filename\n", os.Args[0])
	fmt.Println()
}

func extractBucketAndFilename(proto string) (string, string) {
	re := regexp.MustCompile("crabfs:\\/\\/(\\w+)\\/(.*)")
	groups := re.FindStringSubmatch(proto)
	if groups == nil {
		return "", ""
	}

	return groups[1], groups[2]
}

func main() {
	generateFlag := flag.Bool("gen", false, "Generate a private key and use it")
	flag.Parse()
	tail := flag.Args()

	if len(tail) < 3 {
		usage()
		panic("Invalid args")
	}

	privkeyStr := tail[0]
	var privkey crabfsCrypto.PrivKey

	if *generateFlag {
		var err error
		privkey, err = crabfs.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
		privkeyFile, err := os.Create(privkeyStr)
		if err != nil {
			panic(err)
		}

		data, _ := privkey.Marshal()
		privkeyFile.Write(data)

		privkeyFile.Close()
	} else {
		privkeyFile, err := os.Open(privkeyStr)
		if err != nil {
			panic(err)
		}

		privkey, err = crabfs.ReadPrivateKey(privkeyFile)
		if err != nil {
			panic(err)
		}

		privkeyFile.Close()
	}

	srcStr := tail[1]
	dstStr := tail[2]

	tmpdir, err := ioutil.TempDir("", "crabfs")
	if err != nil {
		panic(err)
	}

	fs, err := crabfs.New(
		crabfsOpts.Context(context.Background()),
		crabfsOpts.Root(tmpdir),
		crabfsOpts.BootstrapPeersAppend([]string{"/ip4/34.73.186.21/tcp/1717/ipfs/QmQ1WzF2HdB53t3BSF3bCLbnwtfaJgDeTmxdyYDL2eTaeL"}),
	)
	if err != nil {
		panic(err)
	}
	defer fs.Close()

	if err := fs.PublishPublicKey(privkey.GetPublic()); err != nil {
		panic(err)
	}

	var srcReader io.Reader
	var dst *os.File
	pushToCrab := false

	if strings.HasPrefix(srcStr, "crabfs://") {
		bucket, filename := extractBucketAndFilename(srcStr)
		fetcher, err := fs.Get(context.Background(), privkey, bucket, filename)
		if err != nil {
			panic(err)
		}
		defer fetcher.Close()
		srcReader = fetcher
	} else {
		file, err := os.Open(srcStr)
		if err != nil {
			panic(err)
		}
		defer file.Close()

		srcReader = file
	}

	if strings.HasPrefix(dstStr, "crabfs://") {
		pushToCrab = true
		dst, err = ioutil.TempFile("", "crabfs_")
		if err != nil {
			panic(err)
		}
	} else {
		dst, err = os.Create(dstStr)
		if err != nil {
			panic(err)
		}
	}

	n, err := io.Copy(dst, srcReader)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Copied %v byte(s)\n", n)

	if pushToCrab {
		bucket, filename := extractBucketAndFilename(dstStr)
		reader, err := os.Open(dst.Name())
		if err != nil {
			panic(err)
		}
		defer reader.Close()

		if err := fs.Put(context.Background(), privkey, bucket, filename, reader, time.Now()); err != nil {
			panic(err)
		}

		fmt.Printf("Pushed to crabfs. Now seeding... Press ctrl+c to exit\n")

		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		s := <-c
		fmt.Println("Got signal:", s)
		os.Exit(0)
	}
}
