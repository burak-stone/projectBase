const mongoose = require('mongoose');
const Enum = require('../../config/Enum');
const CustomError = require('../../lib/Error');
const bcrypt = require("bcryptjs")
const {DEFAULT_LANG} = require("../../config")


const schema = mongoose.Schema({
    email : {type : String, required: true, unique: true} ,
    password : {type : String, required: true} ,
    is_active : {type : Boolean, default: true} ,
    first_name : String ,
    last_name : String ,
    phone_number : String ,
    language : {type: String, default: DEFAULT_LANG}
},{
    versionKey: false,
    timestamps: {
        createdAt : 'created_at',
        updatedAt : 'updated_at'
    }
})


class Users extends mongoose.Model {

    async validPassword(password){
        return await bcrypt.compare(password, this.password)
    }

    static validateFieldsBeforeAuth(email, password) {
        if (typeof password !== "string" || password.length < Enum.PASS_LENGTH)
            throw new CustomError(Enum.HTTP_CODES.UNAUTHORIZED, "Validation Error", "email or password wrong");
        return null;
    }

}

schema.loadClass(Users);
module.exports = mongoose.model('users', schema)