package go_gin_zauth

const AuthPrefix = "Bearer "

//func GetZAuthMiddleware(pubKeys []string) func(c *gin.Context) {
//	return func(c *gin.Context) {
//		// get token from header
//		auth := c.Request.Header.Get("Authorization")
//		if len(auth) > 0 {
//			if !strings.HasPrefix(auth, AuthPrefix) {
//				//c.JSON() 不同应用响应字段不一样，这部分再应用里实现
//				c.Abort()
//			}
//
//		}
//	}
//}
