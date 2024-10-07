const express = require('express');
const router = express.Router();

router.get('/', (req, res, next)=>{
    res.json({
        body: req.body,
        params: req.params,
        query: req.query,
        headers: req.headers
    })
})


module.exports= router;