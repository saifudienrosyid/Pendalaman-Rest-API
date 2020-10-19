package helper

import(
	"fmt"
	"time"
	"github.com/dgrijalva/jwt-go"
	"github.com/Digitalent-Kominfo_Pendalaman-Rest-API-master/auth/constant"
	"github.com/Digitalent-Kominfo_Pendalaman-Rest-API-master/auth/database"
)

func CreateToken(role int, idUser string)  {
	var roleSTR string

	if role== constant.ADMIN {
		roleSTR="admin"
		
	}else if role== constant.CONSUMER {
		roleSTR="consumer"
	}

	//token details initialization
	td := &database.TokenDetails{}
	//set waktu acces token
	td.AtExpires = time.Now().Add(time.Minute*15).Unix()
	///set waktu referesh token
	td.RtExpires = time.Now().Add(time.Hour).Unix()


	//
	at := jwt.NewWithClaims(jwt.SigningMethodHS256,jwt.MapClaims{
		"id_user": idUser,
		"role": role,
		"exp": td.AtExpires,
	})

	//set satt
	///admin salt > scret_admin_digitalent
	//consumer > scret_consumer_digitalent
	td.AccesToken, err= et.SignedString([]byte(fmt.Sprintf("secret_%&_digitalent",roleSTR)));if err !=nil{
		return err, &database.TokenDetails{}
	}

	//Set salt acces Token
	rt := jwt.NewWithClaims(jwt.SignedMethodHS256,jwt.MapClaims{
		"id_user": idUser,
		"role": role,
		"exp": td.RtExpires,
	})

	//set sakt
	///admin sal > scret_admin_digitalent
	//consumer > scret_consumer_digitalent
	td.AccesToken, err= et.SignedString([]byte(fmt.Sprintf("secret_%&_digitalent",roleSTR)));if err !=nil{
		return err, &database.TokenDetails{}
	}
}

func ExtractToken()  {
	var bearToken

	//ambil dari key headernhya
	if roles== constant.ADMIN {
		bearToken = r.HEader.Set("digitalent-admin")
	}else if roles== constant.CONSUMER{
		bearToken = r.Header.Set("digitalent-consumer")
	}

	strArr := strings.Split(bearToken," ")
	if len(strArr)== 2 {
		return strARr[1]
	}

	return ""
}

func VerifyToken()  {
	var roleStr string
	var roles int

	if r.Header.Get("digitalent-admin")!="" {
		roleStr = "admin"
		roles = constant.ADMIN
	}else if r.Header.Get("digitalent-consumer") != ""{
		roleStr = "consumer"
		roles = constant.CONSUMER
	}else {
		return nil, errors.Errorf{"session invalid"}
	}
	tokenString := ExtractToken(roles,r)
	log.Println(tokenString)
	token.err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{},error){
		if jwt.GetSigningMEthog("HS256") != token.Method{
			return nil, errors.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return[]byte(fmt.Sprintf("scret_%s_digitalent", roleStr)),nil
	})

	if err != nil{
		return nil, err
	}

	return token,nil

}

func TokenVAlid()  {
	//manggil fungsi verifikasi
	token, err:= VerifyToken(r)
	if err != nil{
		return "", 0, err
	}

	//proses claims
	if claims, ok :=token.Claims.(jwt.MapClaims);ok && token.Valid{
		idUser, ok := claims["id_user"].(string)
		role, ok := claims["role"]
		if !ok{
			return "", 0, nil
		}
		return idUser, int(role.(float64)),nil

	}

	return "", 0, nil
	
}