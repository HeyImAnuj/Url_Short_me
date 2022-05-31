import bcrypt from 'bcrypt'
import { Request, Response } from 'express'
import { UserStore } from '../store/UserStore'

export default async ({ body: { email, password }}: Request, res: Response) => {
    if(!email || !password) return res.status(400).send({ message: 'missing email or password' })
    email = email.trim().toLowerCase()
    password = password.trim()

    if(UserStore.find(user => user.email === email)) return res.status(409).send({ message: 'user already exists' })

    const salt = await bcrypt.genSalt(10)
    password = await bcrypt.hash(password, salt)

    UserStore.push({ email, password, links: [], isAdmin: false })
    res.status(201).send({ message: 'user registered successfully!' })
}