const mongoose = require('mongoose');

const schema = mongoose.schema({
    is_active : {type : Boolean, default: true} ,
    created_by : {
        type : mongoose.SchemaTypes.ObjectId,
        required: true
    }
},{
    versionKey: false,
    timestapms: {
        createdAt : 'created_at',
        updatedAt : 'updated_at'
    }
})


class Categories extends mongoose.Model {

}

schema.loadClass(Categories);
module.exports = mongoose.model('categories', schema)