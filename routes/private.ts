import { Request, Response } from 'express'
import { IRequest } from '../middlewares/auth'
import { getKey, updateKey } from '../store/State'
import { UriData, UriStore } from '../store/UriStore'
import { UserStore } from '../store/UserStore'


const indexOf = (email: string): number => {
    for(let i = 0; i < UserStore.length; ++i) {
        if(UserStore[i].email === email) {
            return i
        }
    }
    return -1
}

export const Shorten = ({ user, body: { uri }}: IRequest, res: Response) => {
    const key = getKey()
    updateKey()
    UriStore[key] = { value: uri, clicked: 0}

    const idx = indexOf(user.email)
    UserStore[idx].links.push(key)

    res.status(201).send({ 'uri': key })
}

export const Info = ({ user }: IRequest, res: Response) => {
    const idx = indexOf(user.email)
    const { links } = UserStore[idx] 

    const response: Record<string, UriData>[] = []
    links.forEach(link => response.push({ [link] : UriStore[link] }))

    res.status(200).send(response)
}

export const Admin = (_: IRequest, res: Response) => {
    const response: string[] = UserStore.map(user => user.email)

    res.status(200).send(response)
}