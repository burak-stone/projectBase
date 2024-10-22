var express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require("jwt-simple")
const Users = require('../db/models/Users');
const Response = require('../lib/Response');
const CustomError = require('../lib/Error');
const Enum = require('../config/Enum');
const UserRoles = require('../db/models/UserRoles');
const Roles = require("../db/models/Roles")
const config = require("../config")
var router = express.Router();
const auth = require("../lib/auth")();
const AuditLogs= require("../lib/AuditLogs")
const logger = require("../lib/logger/LoggerClass");
const RolePrivileges = require('../db/models/RolePrivileges');

const privileges = require("../config/role_privileges")


//we dont know that emails are the real emails
router.post('/register', async(req,res) => {
  let body = req.body
  try {

    let user = await Users.findOne({})

    if(user){
      return res.sendStatus(Enum.HTTP_CODES.NOT_FOUND)
    }
    if(!body.email) throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, "Validation Error!", "email field must be filled!") 
    if(!body.password) throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, "Validation Error!", "password field must be filled!") 
    if(body.password.length < Enum.PASS_LENGTH){
      throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, "Validation Error!", "Password length must greater than" + Enum.PASS_LENGTH)
    }

    let password = bcrypt.hashSync(body.password, bcrypt.genSaltSync(8), null);
  
    let createdUser = await Users.create({
      email : body.email,
      password,
      is_active: true,
      first_name: body.first_name,
      last_name: body.last_name,
      phone_number: body.phone_number
    })
   
    let role = await Roles.create({
      role_name: Enum.SUPER_ADMIN,
      is_active: true,
      created_by: createdUser._id
    })

    let permissions = privileges.privileges.map(privilege => privilege.key);

    for (let i = 0 ;i < permissions.length ; i++){
      let priv = new RolePrivileges({
          role_id: role._id,
          permission: permissions[i],
          created_by: createdUser._id
      });

      await priv.save();
    }
      

    await UserRoles.create({
      role_id: role._id,
      user_id: createdUser._id
    })


    res.status(Enum.HTTP_CODES.CREATED).json(Response.successResponse({success: true}, Enum.HTTP_CODES.CREATED))

    AuditLogs.info(req.user?.email, "Users", "Register", createdUser)
    logger.info(req.user?.email, "Users", "Register", createdUser)

  } catch (error) {
    logger.info(req.user?.email, "Users", "Register", error)
    let errorResponse = Response.errorResponse(error)
    res.status(errorResponse.code).json(errorResponse)
  }
})

router.post('/auth', async(req,res)=>{
  try {
    let {email, password} = req.body;

    Users.validateFieldsBeforeAuth(email,password)

    let user =  await Users.findOne({email})

    if (!user){
      throw new CustomError(Enum.HTTP_CODES.UNAUTHORIZED, "Validation Error", "email or password wrong")
    }

    if(!user.validPassword(password)){
      throw new CustomError(Enum.HTTP_CODES.UNAUTHORIZED, "Validation Error", "email or password wrong")

    }

    let payload = {
      id: user._id,
      exp: parseInt(Date.now()/ 1000) * config.JWT.EXPIRE_TIME
    }
    let token = jwt.encode(payload, config.JWT.SECRET)

    let userData = {
      _id: user._id,
      first_name: user.first_name,
      last_name: user.last_name
    }

    res.json(Response.successResponse({token, user: userData}))

  } catch (error) {
    let errorResponse = Response.errorResponse(error)
    res.status(errorResponse.code).json(errorResponse)
  }
})

router.all("*", auth.authenticate(), (req, res, next)=>{
  next()
})

/* GET users listing. */
router.get('/',auth.checkRoles("user_view"), async(req, res ) => {

  try {

    let users = await Users.find({})

    res.json(Response.successResponse(users))
    
  } catch (error) {
    let errorResponse = Response.errorResponse(error)
    res.status(errorResponse.code).json(errorResponse)
  }

});

// we dont know that emails are the real emails
router.post('/add', auth.checkRoles("user_add"),  async(req,res) => {
  let body = req.body
  try {

    if(!body.email) throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, "Validation Error!", "email field must be filled!") 
    if(!body.password) throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, "Validation Error!", "password field must be filled!") 
    if(body.password.length < Enum.PASS_LENGTH){
      throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, "Validation Error!", "Password length must greater than" + Enum.PASS_LENGTH)
    }
    if(!body.roles || !Array.isArray(body.roles) || body.roles.length == 0 ){
      throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, "Validation Error!", "roles field must be an array!")
    }
    
    let roles = await Roles.find({_id: {$in: body.roles}})

    if (roles.length == 0 ) {
      throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, "Validation Error!", "roles field must be an array!")
    }

    let password = bcrypt.hashSync(body.password, bcrypt.genSaltSync(8), null);


    let user = await Users.create({
      email : body.email,
      password,
      is_active: true,
      first_name: body.first_name,
      last_name: body.last_name,
      phone_number: body.phone_number
    })

    for (let i=0; i< roles.length; i++ ){
      await UserRoles.create({
        role_id: roles[i]._id,
        user_id: user._id
      })
    }


    AuditLogs.info(req.user.email, "Users", "Add", user)
    logger.info(req.user.email, "Users", "Add", user)
    res.status(Enum.HTTP_CODES.CREATED).json(Response.successResponse({success: true}, Enum.HTTP_CODES.CREATED))

  } catch (error) {
    logger.error(req.user.email, "Users", "Add", error)
    let errorResponse = Response.errorResponse(error)
    res.status(errorResponse.code).json(errorResponse)
  }
})


router.post("/update", auth.checkRoles("user_update"), async (req, res) => {
  let body = req.body;

  // Yardımcı Fonksiyonlar
  function prepareUserUpdates(body) {
    let updates = {};

    // Şifre güncellemesi
    if (body.password && body.password.length >= Enum.PASS_LENGTH) {
        updates.password = bcrypt.hashSync(body.password, bcrypt.genSaltSync(8), null);
    }

    // is_active güncellemesi
    if (typeof body.is_active === "boolean") {
        updates.is_active = body.is_active;
    }

    // first_name güncellemesi
    if (body.first_name) {
        updates.first_name = body.first_name;
    }

    // last_name güncellemesi
    if (body.last_name) {
        updates.last_name = body.last_name;
    }

    // phone_number güncellemesi
    if (body.phone_number) {
        updates.phone_number = body.phone_number;
    }

    return updates;
  }

  async function updateUserRoles(body, existingRoles) {
    let updateLogs = {};

    // Yeni ve silinen rolleri bul
    let removedRoles = existingRoles.filter(x => !body.roles.includes(x.role_id));
    let newRoles = body.roles.filter(x => !existingRoles.map(r => r.role_id).includes(x));

    // Silinen roller
    if (removedRoles.length > 0) {
        await UserRoles.deleteMany({ _id: { $in: removedRoles.map(x => x._id.toString()) } });
        updateLogs.removed_roles = removedRoles.map(x => x.role_id);
    }

    // Yeni eklenen roller
    if (newRoles.length > 0) {
        let newRoleDocs = newRoles.map(role_id => ({
            role_id,
            user_id: body._id
        }));
        await UserRoles.insertMany(newRoleDocs);
        updateLogs.new_roles = newRoles;
    }

    return updateLogs;
  }

  try {
      if (!body._id) {
          throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, "Validation Error!", "_id field must be filled");
      }

      let existingUser = await Users.findById(body._id);
      
      // check the user
      if (!existingUser) {
          throw new CustomError(Enum.HTTP_CODES.NOT_FOUND, "User not found", "User not found");
      }

      // Kullanıcı bilgilerini güncelle
      let updates = prepareUserUpdates(body);

      let updateLogs = {};

      // Kullanıcı rolleri güncellemesi
      if (Array.isArray(body.roles) && body.roles.length > 0) {
          let existingRoles = await UserRoles.find({ user_id: body._id });
          let roleLogs = await updateUserRoles(body, existingRoles);
          updateLogs = { ...updateLogs, ...roleLogs };
      }

      // Veritabanında kullanıcıyı güncelle
      await Users.updateOne({ _id: body._id }, updates);

      // Loglama
      let logData = {
          updated_user_id: body._id,
          updates: { ...updates, ...updateLogs }
      };

      AuditLogs.info(req.user.email, "Users", "Update", logData);
      logger.info(req.user.email, "Users", "Update", logData);

      res.json(Response.successResponse({ success: true }));
  } catch (error) {
      logger.error(req.user.email, "Users", "Update", error)
      let errorResponse = Response.errorResponse(error)
      res.status(errorResponse.code).json(errorResponse)
  }
});

router.post("/delete", auth.checkRoles("user_delete"), async(req,res) =>{
  try {
    let body = req.body
    if(!body._id) throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, "Validation Error!", "_id field must be filled")

    await Users.deleteOne({_id: body._id})

    await UserRoles.deleteMany({user_id: body._id})


    res.json(Response.successResponse({success: true}))
    AuditLogs.info(req.user.email, "Users", "Delete", {deleted_user: body._id})
    logger.info(req.user.email, "Users", "Delete", {deleted_user: body._id})

  } catch (error) {

    logger.error(req.user.email, "Users", "Delete", error)
    let errorResponse = Response.errorResponse(error)
    res.status(errorResponse.code).json(errorResponse)
  }
})



module.exports = router;
