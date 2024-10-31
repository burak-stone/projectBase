const xlsx = require("node-xlsx")
const CustomError = require("./Error")
const {HTTP_CODES} = require("../config/Enum")



class Import{



    constructor(){

    }

    fromExcel(filePath){

        let workSheet = xlsx.parse(filePath);
        if(!workSheet || workSheet.length == 0 ) {throw new CustomError(HTTP_CODES.BAD_REQUEST, "Invalid Excel Format", "Invalid Excel Format")}

        let rows = workSheet[0].data

        if(rows?.length == 0 ){throw new CustomError(HTTP_CODES.NOT_ACCEPTABLE, "File is empty!", "File is empty!")}
        return rows
    }

}

module.exports = Import