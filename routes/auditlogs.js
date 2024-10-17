const express = require('express');
const moment = require("moment")
const router = express.Router();
const Response = require("../lib/Response")
const AuditLogs = require("../db/models/AuditLogs")

router.post('/', async(req, res)=>{
    try {
        let body = req.body
        let query = {}
        let skip= body.skip 
        let limit= body.limit

        if(typeof body.skip !== "numeric"){
            skip = 0
        }
        
        if(typeof body.limit !== "numeric" || body.limit > 500){
            limit =500
        }

        if(body.begin_date && body.end_date){
            query.created_at = {
                $gte: moment(body.begin_date), //greater than or equal begin_date
                $lte: moment(body.end_date) //lower than or equal begin_date
            }
        } else {
            query.created_at = {
                $gte: moment().subtract(1,"day").startOf("day"), 
                $lte: moment() 
            }
        }

        let auditLogs = await AuditLogs.find(query).sort({created_at: -1}).skip(skip).limit(limit)
        res.json(Response.successResponse(auditLogs))

    } catch (error) {
    let errorResponse = Response.errorResponse(error)
    res.status(errorResponse.code).json(errorResponse)
    }
})


module.exports= router;