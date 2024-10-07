const mongoose = require('mongoose');

const schema = mongoose.schema({
    level : String ,
    email : String ,
    location : String,
    proc_type : String,
    log : String,
},{
    versionKey: false,
    timestapms: {
        createdAt : 'created_at',
        updatedAt : 'updated_at'
    }
})


class AuditLogs extends mongoose.Model {

}

schema.loadClass(AuditLogs);
module.exports = mongoose.model('audit_logs', schema)