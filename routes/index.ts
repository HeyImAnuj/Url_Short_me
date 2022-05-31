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
