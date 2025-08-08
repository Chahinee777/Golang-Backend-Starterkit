package feature1

import (
	"fmt"
	"strconv"

	u "example.com/utils"
	"github.com/gin-gonic/gin"
)

type Feature1Handler struct {
}

func Hellohandler(c *gin.Context) {
	id := c.Query("id")

	myint, err := strconv.Atoi(id)
	if err != nil {
		msg := fmt.Sprintf("Error conversion ID:%s", id)
		u.BadRequest(c, "ERR_BAD_ID", msg, err.Error())
	}

	u.OK(c, myint)
}
