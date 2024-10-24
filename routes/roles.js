const express = require("express");
const router= express.Router();
const Response = require("../lib/Response")
const Roles = require("../db/models/Roles");
const RolePrivileges = require("../db/models/RolePrivileges");
const CustomError = require("../lib/Error");
const Enum = require("../config/Enum");
const auth = require("../lib/auth")();
const role_privileges = require("../config/role_privileges");
const config = require("../config");
const i18n = new (require("../lib/i18n"))(config.DEFAULT_LANG);


router.all("*", auth.authenticate(), (req, res, next)=>{
    next()
})

router.get("/",auth.checkRoles("role_view"),async(req,res) => {
    try {
        let roles  = await Roles.find({});
        
        res.json(Response.successResponse(roles));
    } catch (error) {
        let errorResponse = Response.errorResponse(error);
        res.status(errorResponse.code).json(error)
    }
})

router.post("/add", auth.checkRoles("role_add"), async(req,res)=>{
    let body = req.body
    try {

        if(!body.role_name) throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, i18n.translate("COMMON.VALIDATION_ERROR_TITLE", req.user.language), i18n.translate("COMMON.FIELD_MUST_BE_FILLED", req.user.language, ["role_name"]))
        if(!body.permissions || !Array.isArray(body.permissions) || body.permissions.length == 0){
            throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, i18n.translate("COMMON.VALIDATION_ERROR_TITLE", req.user.language), i18n.translate("COMMON.FIELD_MUST_BE_TYPE", req.user.language, ["permissions" , "array"]))
        }

        let role = new Roles({
            role_name: body.role_name,
            is_active: true,
            created_by: req.user?.id
        })


        await role.save();

        for (let i = 0 ;i < body.permissions.length ; i++){
            let priv = new RolePrivileges({
                role_id: role._id,
                permission: body.permissions[i],
                created_by: req.user?.id
            });

            let savedPriv = await priv.save();
            console.log("Saved privilege: " + savedPriv); 
        }

        res.json(Response.successResponse({success: true}))
    } catch (error) {
        let errorResponse = Response.errorResponse(error)
        res.status(errorResponse.code).json(errorResponse)
    }
})

router.post("/update", auth.checkRoles("role_update"), async(req,res)=>{
    let body = req.body
    try {

        if(!body._id) throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, i18n.translate("COMMON.VALIDATION_ERROR_TITLE", req.user.language), i18n.translate("COMMON.FIELD_MUST_BE_FILLED", req.user.language, ["_id"]))
        let updates = {};

        if (body.role_name) updates.role_name = body.role_name
        if (typeof body.is_active === "boolean") updates.is_active = body.is_active

        if(body.permissions && Array.isArray(body.permissions) && body.permissions.length > 0){
       
            let permissions = await RolePrivileges.find({role_id: body._id})


            //body.permissions => ["category_view", "user_add"]
            // permissions => [{role_id: "abc", permission : "user_add", _id: "bcd"}]
            let removedPermissions = permissions.filter( x => !body.permissions.includes(x.permission)) 
            let newPermissions = body.permissions.filter( x => !permissions.map(p => p.permission).includes(x))
            
            
            if (removedPermissions.length > 0 ){
                await RolePrivileges.deleteMany({ _id: { $in: removedPermissions.map(x => x._id) } });
            }

            if(newPermissions.length > 0) {
                for (let i = 0 ;i < newPermissions.length ; i++){
                    let priv = new RolePrivileges({
                        role_id: body._id,
                        permission: newPermissions[i],
                        created_by: req.user?.id
                    });
        
                    await priv.save()
                }
            }
       
        }

        await Roles.updateOne({_id : body._id}, updates);

        res.json(Response.successResponse({success: true}))
    } catch (error) {
        let errorResponse = Response.errorResponse(error)
        res.status(errorResponse.code).json(errorResponse)
    }
})

router.post("/delete", auth.checkRoles("role_delete"), async(req,res)=>{
    let body = req.body
    try {

        if(!body._id) throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, i18n.translate("COMMON.VALIDATION_ERROR_TITLE", req.user.language), i18n.translate("COMMON.FIELD_MUST_BE_FILLED", req.user.language, ["_id"]))

        await Roles.deleteOne({_id : body._id})

        res.json(Response.successResponse({success: true}))
    } catch (error) {
        let errorResponse = Response.errorResponse(error)
        res.status(errorResponse.code).json(errorResponse)
    }
})

router.get("/role_privileges", async(req,res) =>{
    res.json(role_privileges);
})

module.exports = router;
