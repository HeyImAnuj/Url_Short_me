import { URI_LENGTH } from '../constants'

let state = new Array(URI_LENGTH).fill('a')

export const getKey = (): string => state.reduce((x, acc) => acc += x)
export const updateKey = (): void => {
    let idx = 0
    for(let i = 0; i < URI_LENGTH; ++i) {
        if(state[i] < 'z') {
            state[i] = String.fromCharCode(state[i].charCodeAt(0) + 1)
            idx = i
            break
        }
    }
    for(let i = 0; i < idx; ++i) {
        state[i] = 'a'
    }
}

