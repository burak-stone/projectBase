var express = require('express');
var router = express.Router();
const Categories = require('../db/models/Categories');
const Response = require('../lib/Response');
const CustomError = require('../lib/Error')
const Enum = require('../config/Enum')
const AuditLogs= require("../lib/AuditLogs")
const logger = require("../lib/logger/LoggerClass");
const config = require('../config');
const auth = require("../lib/auth")();
const i18n = new (require("../lib/i18n"))(config.DEFAULT_LANG);
const emitter = require("../lib/Emitter")
const excelExport = new (require("../lib/Export"))();
const fs = require("fs")
const Import = new (require("../lib/Import"))();
const multer = require("multer");
const path = require('path');


let multerStorage = multer.diskStorage({
    destination: (req, file, next) => {
        next(null, config.FILE_UPLOAD_PATH)
    },
    filename: (req, file, next) => {
        next(null, file.fieldname + "_" + Date.now() + path.extname(file.originalname));
    }
})

const upload = multer({ storage: multerStorage }).single("pb_file");


router.all("*", auth.authenticate(), (req, res, next)=>{
    next()
})

/* GET categories listing. */
router.get('/',auth.checkRoles("category_view"), async(req, res) => {

    try {
        let categories = await Categories.find({});

        res.json(Response.successResponse(categories));
    } catch (error) {
        let errorResponse = Response.errorResponse(error)

        res.status(errorResponse.code).json(Response.errorResponse(error))
    }
});


router.post('/add',auth.checkRoles("category_add"), async(req, res)=>{
    let body = req.body;
    try {
        
        if(!body.name) throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, i18n.translate("COMMON.VALIDATION_ERROR_TITLE", req.user.language), i18n.translate("COMMON.FIELD_MUST_BE_FILLED", req.user.language, ["name"]))
        let category = new Categories({
            name: body.name,
            is_active: body.is_active,
            created_by: req.user.id
        })

        await category.save();
        AuditLogs.info(req.user.email, "Categories", "Add", category)
        logger.info(req.user.email, "Categories", "Add", category)
        emitter.getEmitter("notifications").emit("messages", {message: category.name+ " is added"})
        res.json(Response.successResponse({success: true}));

    } catch (error) {
        logger.error(req.user.email, "Categories", "Add", error)
        let errorResponse = Response.errorResponse(error)
        res.status(errorResponse.code).json(errorResponse);
    }

})


router.post("/update",auth.checkRoles("category_update"), async(req,res)=>{
    let body = req.body;

    try {

        if(!body._id) throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, i18n.translate("COMMON.VALIDATION_ERROR_TITLE", req.user.language), i18n.translate("COMMON.FIELD_MUST_BE_FILLED", req.user.language, ["_id"]))

        let updates = {};
        
        if(body.name) updates.name= body.name;

        if(typeof body.is_active === 'boolean') updates.is_active= body.is_active;

        await Categories.updateOne({ _id: body._id }, updates);

        res.json(Response.successResponse({success: true}));
        AuditLogs.info(req.user.email, "Categories", "Update", {updated_category_id: body._id, ...updates})
        logger.info(req.user.email, "Categories", "Update", {updated_category_id: body._id, ...updates})

    } catch (error) {
        let errorResponse = Response.errorResponse(error)
        res.status(errorResponse.code).json(errorResponse);
        logger.error(req.user.email, "Categories", "Update", error)
    }
})

router.post("/delete", auth.checkRoles("category_delete"), async(req,res)=>{
    let body = req.body;

    try {
        if(!body._id) throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, i18n.translate("COMMON.VALIDATION_ERROR_TITLE", req.user.language), i18n.translate("COMMON.FIELD_MUST_BE_FILLED", req.user.language, ["_id"]))

        await Categories.deleteOne({_id : body._id});

        res.json(Response.successResponse({success: true}));
        logger.info(req.user.email, "Categories", "Delete", {deleted_category_id: body._id})
        AuditLogs.info(req.user.email, "Categories", "Delete", {deleted_category_id: body._id})
    } catch (error) {
        let errorResponse = Response.errorResponse(error)
        res.status(errorResponse.code).json(errorResponse);
        logger.error(req.user.email, "Categories", "Delete", error)
    }
})

router.post("/export", auth.checkRoles("category_export") , async(req,res) => {
    try {
        let categories = await Categories.find({});
        let excel= excelExport.toExcel(
            ["NAME","IS ACTIVE ?", "USER ID" , "CREATED AT" , "UPDATED AT"],
            ["name", "is_active", "created_by" , "created_at", "updated_at"],
            categories
        )

        // eslint-disable-next-line no-undef
        let filePath = __dirname+ "/../tmp/categories_excel_" + Date.now()+ ".xlsx"

        fs.writeFileSync(filePath, excel, "UTF-8")
        res.download(filePath)
        //fs.unlinkSync(filePath)

    } catch (error) {
        let errorResponse = Response.errorResponse(error)

        res.status(errorResponse.code).json(Response.errorResponse(error))
    }
})

router.post("/import", auth.checkRoles("category_add"), upload, async (req, res) => {
    try {

        let file = req.file;

        let rows = Import.fromExcel(file.path);

        for (let i = 1; i < rows.length; i++) {
            // eslint-disable-next-line no-unused-vars
            let [name, is_active, user, created_at, updated_at] = rows[i];
            if (name) {
                let createdCategories = await Categories.create({
                    name,
                    is_active,
                    created_by: req.user._id
                });

                AuditLogs.info(req.user.email, "Categories", "Add", createdCategories)
                logger.info(req.user.email, "Categories", "Add", createdCategories)
                emitter.getEmitter("notifications").emit("messages", {message: createdCategories.name+ " is added"})
            }

        }

        res.status(Enum.HTTP_CODES.CREATED).json(Response.successResponse(req.body, Enum.HTTP_CODES.CREATED));

    } catch (error) {
        logger.error(req.user.email, "Categories", "Add", error)
        let errorResponse = Response.errorResponse(error);
        res.status(errorResponse.code).json(Response.errorResponse(error));
    }
})

module.exports = router;
