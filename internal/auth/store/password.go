package store

import "golang.org/x/crypto/bcrypt"

// MinCost を使うのはテスト/エミュレータ用途で本物の Supabase より弱いセキュリティで構わないため。
func HashPassword(pw string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
}

func VerifyPassword(hash []byte, pw string) bool {
	return bcrypt.CompareHashAndPassword(hash, []byte(pw)) == nil
}
