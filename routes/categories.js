var express = require('express');
var router = express.Router();
const Categories = require('../db/models/Categories');
const Response = require('../lib/Response');
const CustomError = require('../lib/Error')
const Enum = require('../config/Enum')

/* GET categories listing. */
router.get('/', async(req, res) => {

    try {
        let categories = await Categories.find({});

        res.json(Response.successResponse(categories));
    } catch (error) {
        let errorResponse = Response.errorResponse(error)

        res.status(errorResponse.code).json(Response.errorResponse(error))
    }
});


router.post('/add', async(req, res)=>{
    let body = req.body;
    try {
        
        if(!body.name) throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, 'Validation Error!', 'Name field must be filled.')
        let category = new Categories({
            name: body.name,
            is_active: body.is_active,
            created_by: req.user?.id
        })

        await category.save();

        res.json(Response.successResponse({success: true}));

    } catch (error) {
        let errorResponse = Response.errorResponse(error)
        res.status(errorResponse.code).json(errorResponse);
    }

})


router.post("/update",async(req,res)=>{
    let body = req.body;

    try {

        if(!body._id) throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, 'Validation Error!', '_id field must be filled.')

        let updates = {};
        
        if(body.name) updates.name= body.name;

        if(typeof body.is_active === 'boolean') updates.is_active= body.is_active;

        await Categories.updateOne({ _id: body._id }, updates);

        res.json(Response.successResponse({success: true}));


    } catch (error) {
        let errorResponse = Response.errorResponse(error)
        res.status(errorResponse.code).json(errorResponse);
    }
})

router.post("/delete", async(req,res)=>{
    let body = req.body;

    try {
        if(!body._id) throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, 'Validation Error!', '_id field must be filled.')

        await Categories.deleteOne({_id : body._id});

        res.json(Response.successResponse({success: true}));

    } catch (error) {
        let errorResponse = Response.errorResponse(error)
        res.status(errorResponse.code).json(errorResponse);
    }
})


module.exports = router;
