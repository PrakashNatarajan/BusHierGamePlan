package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/go-gorp/gorp"
	_redis "github.com/go-redis/redis/v7"
	_ "github.com/go-sql-driver/mysql" //import mysql
)

//DB ...
type DB struct {
	*sql.DB
}

var db *gorp.DbMap

//Init ...
func Init() {

    dbinfo := os.Getenv("DB_USER") + ":" + os.Getenv("DB_PASS") + "@tcp(" + os.Getenv("DB_HOST") + ":" + os.Getenv("DB_PORT") + ")/" + os.Getenv("DB_NAME")

    fmt.Println(dbinfo)
	var err error
	db, err = ConnectDB(dbinfo)
	if err != nil {
		log.Fatal(err)
	}

}

//ConnectDB ...
func ConnectDB(dataSourceName string) (*gorp.DbMap, error) {
	db, err := sql.Open("mysql", dataSourceName)
	if err != nil {
		return nil, err
	}

	if err = db.Ping(); err != nil {
		return nil, err
	}

	dbmap := &gorp.DbMap{Db: db, Dialect: gorp.MySQLDialect{"InnoDB", "UTF8"}}
	//dbmap.TraceOn("[gorp]", log.New(os.Stdout, "golang-gin:", log.Lmicroseconds)) //Trace database requests
	return dbmap, nil
}

//GetDB ...
func GetDB() *gorp.DbMap {
	return db
}

//RedisClient ...
var RedisClient *_redis.Client

//InitRedis ...
func InitRedis(selectDB ...int) {

	var redisHost = os.Getenv("REDIS_HOST")
	var redisUsername = os.Getenv("REDIS_USERNAME")
	var redisPassword = os.Getenv("REDIS_PASSWORD")

	RedisClient = _redis.NewClient(&_redis.Options{
		Addr:     redisHost,
		Username: redisUsername,
		Password: redisPassword,
		DB:       selectDB[0],
		// DialTimeout:        10 * time.Second,
		// ReadTimeout:        30 * time.Second,
		// WriteTimeout:       30 * time.Second,
		// PoolSize:           10,
		// PoolTimeout:        30 * time.Second,
		// IdleTimeout:        500 * time.Millisecond,
		// IdleCheckFrequency: 500 * time.Millisecond,
		// TLSConfig: &tls.Config{
		// 	InsecureSkipVerify: true,
		// },
	})

}

//GetRedis ...
func GetRedis() *_redis.Client {
	return RedisClient
}
