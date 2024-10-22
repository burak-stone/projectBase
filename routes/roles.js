const express = require("express");
const router= express.Router();
const Response = require("../lib/Response")
const Roles = require("../db/models/Roles");
const RolePrivileges = require("../db/models/RolePrivileges");
const CustomError = require("../lib/Error");
const Enum = require("../config/Enum");
const auth = require("../lib/auth")();
const role_privileges = require("../config/role_privileges");
const AuditLogs= require("../lib/AuditLogs")
const logger = require("../lib/logger/LoggerClass");
const UserRoles = require("../db/models/UserRoles");


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

        if(!body.role_name) throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, "Validation Error!", "role_name field must be filled!")
        if(!body.permissions || !Array.isArray(body.permissions) || body.permissions.length == 0){
            throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, "Validation Error!", "permissions field must be an Array!")
        }

        let role = new Roles({
            role_name: body.role_name,
            is_active: true,
            created_by: req.user.id
        })

        await role.save();

        for (let i = 0 ;i < body.permissions.length ; i++){
            let priv = new RolePrivileges({
                role_id: role._id,
                permission: body.permissions[i],
                created_by: req.user.id
            });

            await priv.save();
        }


        AuditLogs.info(req.user.email, "Roles", "Add", role)
        logger.info(req.user.email, "Roles", "Add", role)
        res.json(Response.successResponse({success: true}))
    } catch (error) {
        logger.error(req.user.email, "Roles", "Add", error)
        let errorResponse = Response.errorResponse(error)
        res.status(errorResponse.code).json(errorResponse)
    }
})

router.post("/update", auth.checkRoles("role_update"), async (req, res) => {
    let body = req.body;
    try {
        if (!body._id) throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, "Validation Error!", "_id field must be filled!");

        let updates = {};
        let update_logs = {};

        // Role'ün mevcut durumunu alın
        let existingRole = await Roles.findById(body._id);

        // update role_name
        if (body.role_name && body.role_name !== existingRole.role_name) {
            updates.role_name = body.role_name;
            update_logs.role_name = {
                old: existingRole.role_name,
                new: body.role_name
            };
        }

        // update is_active
        if (typeof body.is_active === "boolean" && body.is_active !== existingRole.is_active) {
            updates.is_active = body.is_active;
            update_logs.is_active = {
                old: existingRole.is_active,
                new: body.is_active
            };
        }

        // update permissions
        if (body.permissions && Array.isArray(body.permissions) && body.permissions.length > 0) {
            let permissions = await RolePrivileges.find({ role_id: body._id });

            // Silinen ve yeni eklenen izinleri bul
            let removedPermissions = permissions.filter(x => !body.permissions.includes(x.permission));
            let newPermissions = body.permissions.filter(x => !permissions.map(p => p.permission).includes(x));

            if (removedPermissions.length > 0) {
                await RolePrivileges.deleteMany({ _id: { $in: removedPermissions.map(x => x._id) } });
               
                // Silinen izinleri logla
                update_logs.removed_permissions = removedPermissions.map(x => x.permission);
            }

            if (newPermissions.length > 0) {
                for (let i = 0; i < newPermissions.length; i++) {
                    let priv = new RolePrivileges({
                        role_id: body._id,
                        permission: newPermissions[i],
                        created_by: req.user.id
                    });
                    await priv.save();
                }

                // Yeni eklenen izinleri logla
                update_logs.new_permissions = newPermissions;
            }
        }

        // Role güncelle
        await Roles.updateOne({ _id: body._id }, updates);

        // Audit loglar
        AuditLogs.info(req.user.email, "Roles", "Update", update_logs);
        logger.info(req.user.email, "Roles", "Update", update_logs);

        res.json(Response.successResponse({ success: true }));
    } catch (error) {
        logger.error(req.user.email, "Roles", "Update", error);
        let errorResponse = Response.errorResponse(error);
        res.status(errorResponse.code).json(errorResponse);
    }
});

router.post("/delete", auth.checkRoles("role_delete"), async(req,res)=>{
    let body = req.body
    try {
        let role = await Roles.findById(body._id);
        if(!body._id) throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, "Validation Error!", "_id field must be filled!")
        if(!role)throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, "Validation Error!", "role couldn't found!")

        await Roles.deleteOne({_id : body._id})

        await UserRoles.deleteMany({ role_id: body._id });
        await RolePrivileges.deleteMany({ role_id: body._id });

        AuditLogs.info(req.user.email, "Roles", "Delete", {deleted_role_id: body._id})
        logger.info(req.user.email, "Roles", "Delete", {deleted_role_id: body._id})
        res.json(Response.successResponse({success: true}))
    } catch (error) {
        logger.error(req.user.email, "Roles", "Delete", error)
        let errorResponse = Response.errorResponse(error)
        res.status(errorResponse.code).json(errorResponse)
    }
})

router.get("/role_privileges", async(req,res) =>{
    res.json(role_privileges);
})

module.exports = router;
