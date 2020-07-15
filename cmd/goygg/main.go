package main

import (
	"fmt"
	"goygg/internal/config"
	"goygg/internal/ygg"
	"goygg/internal/ygg/model/postgres"
	"log"
	"net/http"

	"github.com/jmoiron/sqlx"
)

func main() {
	conf, err := config.NewConfig("goygg.yaml")
	if err != nil {
		panic(err)
	}

	conn := fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=disable",
		conf.Database.User,
		conf.Database.Password,
		conf.Database.Host,
		conf.Database.Port,
		conf.Database.Dbname,
	)

	db := sqlx.MustOpen("postgres", conn)

	repo, err := postgres.New(db)
	if err != nil {
		panic(err)
	}

	privkey, err := ygg.OpenPrivateKey("private.pem")
	if err != nil {
		panic(err)
	}

	handler := &ygg.Handler{
		Config:     conf,
		Repository: repo,
		PrivateKey: privkey,
	}

	http.Handle("/", handler)

	log.Println("started")

	err = http.ListenAndServe(conf.Listen, nil)
	if err != nil {
		panic(err)
	}
}
