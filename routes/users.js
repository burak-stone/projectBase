var express = require('express');
const bcrypt = require('bcryptjs');
const Users = require('../db/models/Users');
const Response = require('../lib/Response');
const CustomError = require('../lib/Error');
const Enum = require('../config/Enum');
const UserRoles = require('../db/models/UserRoles');
const Roles = require("../db/models/Roles")
var router = express.Router();

/* GET users listing. */
router.get('/', async(req, res ) => {

  try {

    let users = await Users.find({})

    res.json(Response.successResponse(users))
    
  } catch (error) {
    let errorResponse = Response.errorResponse(error)
    res.status(errorResponse.code).json(errorResponse)
  }

});

// we dont know that emails are the real emails
router.post('/add', async(req,res) => {
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

    res.status(Enum.HTTP_CODES.CREATED).json(Response.successResponse({success: true}, Enum.HTTP_CODES.CREATED))

  } catch (error) {
    let errorResponse = Response.errorResponse(error)
    res.status(errorResponse.code).json(errorResponse)
  }
})

router.post("/update", async(req, res) => {
  let body = req.body
  try {
    let updates = {}

    if(!body._id) throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, "Validation Error!", "_id field must be filled")

    if(body.password && body.password.length < Enum.PASS_LENGTH){
      updates.password = bcrypt.hashSync(body.password, bcrypt.genSaltSync(8), null)
    }

    if(typeof body.is_active === "boolean") updates.is_active = body.is_active
    if(body.first_name) updates.first_name = body.first_name
    if(body.last_name) updates.last_name = body.last_name
    if(body.phone_number) updates.phone_number = body.phone_number

    if(Array.isArray(body.roles) && body.roles.length > 0) {

      let userRoles = await UserRoles.find({user_id: body._id})

      let removedRoles = userRoles.filter( x => !body.roles.includes(x.role_id)) 
      let newRoles =  body.roles.filter( x => !userRoles.map(r => r.role_id).includes(x))

      if (removedRoles.length > 0 ){
        await UserRoles.deleteMany({ _id: { $in: removedRoles.map(x => x._id.toString()) } });
      }

      if(newRoles.length > 0) {
        for (let i = 0 ;i < newRoles.length ; i++){
            let userRole = new UserRoles({
                role_id:  newRoles[i],
                user_id: body._id
            });

            await userRole.save()
        }
      }

    }

    await Users.updateOne({_id: body._id}, updates)

    res.json(Response.successResponse({success: true}))
    
  } catch (error) {
    let errorResponse = Response.errorResponse(error)
    res.status(errorResponse.code).json(errorResponse)
  }
})

router.post("/delete", async(req,res) =>{
  try {
    let body = req.body
    if(!body._id) throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, "Validation Error!", "_id field must be filled")

    await Users.deleteOne({_id: body._id})

    await UserRoles.deleteMany({user_id: body._id})

    res.json(Response.successResponse({success: true}))
  } catch (error) {
    let errorResponse = Response.errorResponse(error)
    res.status(errorResponse.code).json(errorResponse)
  }
})

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
   
    await UserRoles.create({
      role_id: role._id,
      user_id: createdUser._id
    })

    

    res.status(Enum.HTTP_CODES.CREATED).json(Response.successResponse({success: true}, Enum.HTTP_CODES.CREATED))

  } catch (error) {
    let errorResponse = Response.errorResponse(error)
    res.status(errorResponse.code).json(errorResponse)
  }
})

module.exports = router;
