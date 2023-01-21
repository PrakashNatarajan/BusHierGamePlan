package main

import (
  "fmt"
  "log"
  "net/http"
  "os"
  "runtime"

  "BusHierGamePlan/controllers"
  "BusHierGamePlan/db"
  "BusHierGamePlan/forms"
  "github.com/gin-contrib/gzip"
  "github.com/joho/godotenv"
  uuid "github.com/twinj/uuid"

  "github.com/gin-gonic/gin"
  "github.com/gin-gonic/gin/binding"
)

//CORSMiddleware ...
//CORS (Cross-Origin Resource Sharing)
func CORSMiddleware() gin.HandlerFunc {
  return func(ctxt *gin.Context) {
    ctxt.Writer.Header().Set("Access-Control-Allow-Origin", "http://localhost")
    ctxt.Writer.Header().Set("Access-Control-Max-Age", "86400")
    ctxt.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, UPDATE")
    ctxt.Writer.Header().Set("Access-Control-Allow-Headers", "X-Requested-With, Content-Type, Origin, Authorization, Accept, Client-Security-Token, Accept-Encoding, x-access-token")
    ctxt.Writer.Header().Set("Access-Control-Expose-Headers", "Content-Length")
    ctxt.Writer.Header().Set("Access-Control-Allow-Credentials", "true")

    if ctxt.Request.Method == "OPTIONS" {
      fmt.Println("OPTIONS")
      ctxt.AbortWithStatus(200)
    } else {
      ctxt.Next()
    }
  }
}

//RequestIDMiddleware ...
//Generate a unique ID and attach it to each request for future reference or use
func RequestIDMiddleware() gin.HandlerFunc {
  return func(ctxt *gin.Context) {
    uuid := uuid.NewV4()
    ctxt.Writer.Header().Set("X-Request-Id", uuid.String())
    ctxt.Next()
  }
}


var empAuths = new(controllers.EmpAuthController)

//EmpAuthMiddleware ...
//JWT Authentication middleware attached to each request that needs to be authenitcated to validate the access_token in the header
func EmpAuthMiddleware() gin.HandlerFunc {
  return func(ctxt *gin.Context) {
    empAuths.TokenValid(ctxt)
    ctxt.Next()
  }
}

func main() {
  //Load the .env file
  err := godotenv.Load(".env")
  if err != nil {
    log.Fatal("error: failed to load the env file")
  }

  if os.Getenv("ENV") == "PRODUCTION" {
    gin.SetMode(gin.ReleaseMode)
  }

  //Start the default gin server
  route := gin.Default()

  //Custom form validator
  binding.Validator = new(forms.DefaultValidator)

  route.Use(CORSMiddleware())
  route.Use(RequestIDMiddleware())
  route.Use(gzip.Gzip(gzip.DefaultCompression))

  //Start PostgreSQL database
  //Example: db.GetDB() - More info in the models folder
  db.Init()

  //Start Redis on database 1 - it's used to store the JWT but you can use it for anythig else
  //Example: db.GetRedis().Set(KEY, VALUE, at.Sub(now)).Err()
  db.InitRedis(0)

  v1 := route.Group("/v1")
  {
    /*** START EMP USER ***/
	empUsers := new(controllers.EmpProsController)

	v1.POST("/user/login", empUsers.Login)
	v1.POST("/user/register", empUsers.Register)
	v1.GET("/user/logout", empUsers.Logout)

	/*** START empAuths ***/
	empAuths := new(controllers.EmpAuthController)

	//Refresh the token when needed to generate new access_token and refresh_token for the user
	v1.POST("/token/refresh", empAuths.Refresh)

	/*** START Article ***/
	article := new(controllers.ArticleController)

	v1.POST("/article", EmpAuthMiddleware(), article.Create)
	v1.GET("/articles", EmpAuthMiddleware(), article.All)
	v1.GET("/article/:id", EmpAuthMiddleware(), article.One)
	v1.PUT("/article/:id", EmpAuthMiddleware(), article.Update)
	v1.DELETE("/article/:id", EmpAuthMiddleware(), article.Delete)
  }

  route.LoadHTMLGlob("./public/html/*")

  route.Static("/public", "./public")

  route.GET("/", func(c *gin.Context) {
    c.HTML(http.StatusOK, "index.html", gin.H{
      "ginBoilerplateVersion": "v0.03",
      "goVersion": runtime.Version(),
    })
  })

  route.NoRoute(func(c *gin.Context) {
    c.HTML(404, "404.html", gin.H{})
  })

  port := os.Getenv("PORT")

  log.Printf("\n\n PORT: %s \n ENV: %s \n SSL: %s \n Version: %s \n\n", port, os.Getenv("ENV"), os.Getenv("SSL"), os.Getenv("API_VERSION"))

  if os.Getenv("SSL") == "TRUE" {

    //Generated using sh generate-certificate.sh
	SSLKeys := &struct {
	  CERT string
	  KEY  string
	}{
	  CERT: "./cert/myCA.cer",
	  KEY:  "./cert/myCA.key",
	}

	route.RunTLS(":"+port, SSLKeys.CERT, SSLKeys.KEY)
  } else {
    route.Run(":" + port)
  }

}
