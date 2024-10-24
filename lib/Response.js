const CustomError = require('./Error')
const config = require("../config")
const Enum = require('../config/Enum')
const i18n = new (require("./i18n"))(config.DEFAULT_LANG);

class Response {

    constructor(){}

    static successResponse(data, code= 200){
        return{
            code,
            data
        }
    }

    static errorResponse(error, lang){

        console.error(error)

        if (error instanceof CustomError){
            return{
                code: error.code,
                error:{
                    message: error.message,
                    description: error.description
                }
            }
        } else if (error.message.includes("E11000")) {
            return{
                code: Enum.HTTP_CODES.CONFLICT,
                error:{
                    message: i18n.translate("COMMON.ALREADY_EXIST", lang),
                    description: i18n.translate("COMMON.ALREADY_EXIST", lang)
                }
            }
        }

        return{
            code: Enum.HTTP_CODES.INT_SERVER_ERROR,
            error:{
                message: i18n.translate("COMMON.UNKNOWN_ERROR", lang),
                description: error.message
            }
        }


        
    }

}

module.exports = Response;