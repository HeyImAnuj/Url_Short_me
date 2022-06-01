A simple Url shortner



//index.ts//
import { Router } from 'express'

import Register from './register'
import Login from './login'
import Public from './public'
import { Shorten, Info, Admin } from './private'

import AuthMiddleware from '../middlewares/auth'
import AdminMiddleware from '../middlewares/admin'

const router = Router()

router.post('/register', Register)
router.post('/login', Login)

router.post('/shorten', AuthMiddleware, Shorten)
router.get('/info', AuthMiddleware, Info)

router.get('/admin', AuthMiddleware, AdminMiddleware, Admin)

router.get('/:key', Public)

export default router

//login.ts//
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import { Request, Response } from 'express'

import { UserStore, UserData } from '../store/UserStore'
import { JWT_SECRET } from '../constants'

export default async ({ body: { email, password } }: Request, res: Response) => {
  if(!email || !password) return res.status(400).send({ message: 'missing email or password!' })
  email = email.trim().toLowerCase()
  password = password.trim()

  const user = UserStore.find(user => user.email === email)
  if(!user) return res.status(401).send({ message: 'no user found, register instead!' })

  const validate = await bcrypt.compare(password, user.password)
  if(!validate) return res.status(401).send({ message: 'invalid credentials!' })
  
  const { isAdmin } = user 
  const token = jwt.sign({ email, isAdmin }, JWT_SECRET)
  return res.status(302).header("xauth", token).send({ message: 'user logged in successfully!', token })
}





//private.ts//
import { Request, Response } from 'express'

import { getKey, updateKey } from '../store/State'
import { UriStore, UriData } from '../store/UriStore'
import { UserStore, UserData } from '../store/UserStore'

import { IRequest } from '../middlewares/auth'

const indexOf = (email: string): number => {
  for(let i = 0; i < UserStore.length; ++i) {
    if(UserStore[i].email === email) {
      return i
    }
  }
  return -1
}

export const Shorten = ({ user, body: { uri } }: IRequest, res: Response) => {
  const key = getKey()
  updateKey()
  UriStore[key] = { value: uri, clicked: 0 }

  const idx = indexOf(user.email)
  UserStore[idx].links.push(key)

  res.status(201).send({ 'uri' : key })
}

type ResponseData = { link: string; value: string; clicked: number; }
export const Info = ({ user }: IRequest, res: Response) => {
  const idx = indexOf(user.email)
  const { links } = UserStore[idx]

  const response: ResponseData[] = [] 
  links.forEach(link => {
    response.push({ link, ...UriStore[link] })
  })

  res.status(200).send(response)
}

export const Admin = (_: IRequest, res: Response) => {
  const response: string[] = UserStore.map(user => user.email) 

  res.status(200).send(response)
}


//public.ts//
import { Request, Response } from 'express'

import { UriStore, UriData } from '../store/UriStore'

export default (req: Request, res: Response) => {
  const key = req.params.key
  if(UriStore[key] == null) return res.status(404).send({ 'message' : 'no url exists for the shortened url' })
  UriStore[key].clicked++
  res.status(301).redirect(UriStore[key].value)
}
Pseudo code
