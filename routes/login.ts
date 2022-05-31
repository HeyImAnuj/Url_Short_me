import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'

import { Request, Response } from 'express'
import { UserStore } from '../store/UserStore'
import { JWT_SECRET } from '../constants'

export default async ({ body: { email, password } }: Request, res: Response) => {
    if(!email || !password) return res.status(400).send({ message: 'missing email or password' })
    email = email.trim().toLowerCase()
    password = password.trim()

    const user = UserStore.find(user => user.email === email)
    if(!user) return res.send(401).send({ message: 'no user found, register instead!' })

    const validate = await bcrypt.compare(password, user.password)
    if(!validate) return res.send(401).send({ message: 'invalid credentials' })

    const { isAdmin } = user

    const token = jwt.sign({ email, isAdmin }, JWT_SECRET)
    res.status(302).header('xauth', token).send({ message: 'user logged in successfully', token })
}