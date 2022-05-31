import bcrypt from 'bcrypt'

import { ADMIN_KEY } from "../constants"
import { UserData, UserStore } from '../store/UserStore'

export default async function() {
    const salt = await bcrypt.genSalt(10)
    const hash = await bcrypt.hash(ADMIN_KEY, salt)

    const admin: UserData = { email: 'admin@short.me', password: hash, isAdmin: true, links: [] }
    UserStore.push(admin)
    console.log('--> Admin Generation Successful')
}