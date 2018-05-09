# jwt-middleware
A middleware for GIN to parse JWT tokens

## How to use
Get the package
```
$ go get github.com/500degrees/jwt-middleware
```

In your application use:
```golang
router := gin.Default()
router.Use(jwtmiddleware.New("secret"))
```
