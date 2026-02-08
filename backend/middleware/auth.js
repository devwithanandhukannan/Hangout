import jwt from 'jsonwebtoken';

export const authMiddleware = (req,res,next) => {
    const token = req.cookies.hangout;
    if(!token){
        return res.status(401).json({message:"No token auth denied!"})
    }
    try {
        const decode = jwt.verify(token, process.env.JWT_SECRET_KEY);
        req.user = {userName : decode.username, userId: decode.userId}
        next();

    }catch(err){
        return res.status(400).json(err)
    }
}