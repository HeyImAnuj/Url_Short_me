import express from 'express'
import bodyParser from 'body-parser'

import { PORT } from './constants'

import Router from './routes'
import AdminGenerator from './generators/admin'

const app = express()
app.use(bodyParser.urlencoded({extended: false}))
app.use(bodyParser.json())

AdminGenerator()

app.use('/', Router)

app.listen(PORT, () => {
    console.log(`--> Listening on PORT : ${PORT}`)
})