package main

import (
	"flag"
	"fmt"
	"log"
)

func seedAccount(store Storage, fname, lname, password string) *Account {
	acc, err := NewAccount(fname, lname, password)
	if err != nil {
		log.Fatal(err)
	}
	if err := store.CreateAccount(acc); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("New account number => %d\n", acc.Number)
	return acc
}

func seedAccounts(s Storage) {
	seedAccount(s, "devansh", "soni", "somethingsomething")
}

func main() {

	seed := flag.Bool("seed", false, "seed the db")
	flag.Parse()
	store, err := NewPostgresStore()
	if err != nil {
		log.Fatal(err)
	}
	if err := store.Init(); err != nil {
		log.Fatal(err)
	}

	if *seed {
		fmt.Println("seeding the db")
		seedAccounts(store)
	}

	server := NewAPIServer(":8000", store)
	server.Run()
}
