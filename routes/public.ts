import { Request, Response } from 'express'

import { UriStore, UriData } from '../store/UriStore'

export default (req: Request, res: Response) => {
    const { key } = req.params
    if(UriStore[key] == null) return res.status(404).send({ message: 'no url exists for the shortened url' })
    UriStore[key].clicked++
    res.status(302).redirect(UriStore[key].value)
}