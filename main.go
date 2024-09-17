package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func main() {
	accessToken := createToken("moriT958")

	// 認証結果を表示
	fmt.Println(string(authenticateUser(accessToken)))
}

// jwtを生成する関数
func createToken(userID string) string {
	// jwt生成の元となる構造体
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 72).Unix(), // 72時間の有効期限
	}

	// token生成
	algorithm := jwt.SigningMethodHS256
	token := jwt.NewWithClaims(algorithm, claims)

	// 署名
	accessToken, _ := token.SignedString([]byte("ACCESS_SECRET_KEY"))

	return accessToken
}

// 認証を行う関数
func authenticateUser(tokenString string) []byte {
	getSecretKey := func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("ACCESS_SECRET_KEY"), nil
	}

	token, err := jwt.Parse(tokenString, getSecretKey)
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// 認証が成功した場合のJSONレスポンス
		response := map[string]interface{}{
			"user_id": claims["user_id"],
			"exp":     claims["exp"],
			"status":  "success",
		}

		// JSON形式に変換して出力
		jsonResponse, _ := json.Marshal(response)
		return jsonResponse

	} else {
		// エラーメッセージをJSON形式で出力
		errorResponse := map[string]interface{}{
			"error":  "Invalid token",
			"status": "failed",
		}
		if err != nil {
			errorResponse["detail"] = err.Error()
		}

		// JSON形式に変換して出力
		jsonErrorResponse, _ := json.Marshal(errorResponse)

		return jsonErrorResponse
	}
}
