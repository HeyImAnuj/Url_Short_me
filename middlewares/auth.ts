import jwt from 'jsonwebtoken'
import { Request, Response, NextFunction } from 'express'


import { JWT_SECRET } from '../constants';

export interface IRequest extends Request {
    [key: string]: any
}

export default (req: IRequest, res: Response, next: NextFunction) => {
    let token = req.headers.authorization;
    if(!token) return res.status(401).send({ message: 'Access Denied / Unauthorized request' })

    try {
        token = token.split(' ')[1]
        if(token === null || !token) return res.status(401).send({ message: 'Unauthorized access' })

        const user = jwt.verify(token, JWT_SECRET)
        if(!user) res.status(401).send({ message: 'Unauthorized access'})

        req.user = user
        next()
    } catch(err) {
        res.status(401).send({ message: 'Invalid token!' })
    }
}