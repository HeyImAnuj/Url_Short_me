type UserData = { email: string; password: string; links: string[]; isAdmin: boolean; }

const UserStore: UserData[] = []

export { UserData, UserStore }