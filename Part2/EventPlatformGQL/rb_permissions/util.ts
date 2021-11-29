import { isArray, isObject, mapValues, mergeWith } from 'lodash';

/**
 * Map where all leafs are of type T.
 */
export type RecMap<T> = T | { [k: string]: T | RecMap<T> };

/**
 * Maps all leafs of an object where leafs have the same type. Leafs are mapped
 * by a callback that is executed if the type guard evaluates to true.
 * @param o Map to transform
 * @param cb Leaf transformer
 * @param guard Leaf type checker
 * @returns Transformed map
 */
export function mapLeafs<T, U>(
    o: RecMap<T>,
    cb: (leaf: T) => U,
    guard: (val: any) => val is T,
): RecMap<U> {
    function rec(val: RecMap<T>): RecMap<U> {
        if (guard(val)) {
            return cb(val);
        } else {
            return mapLeafs(val, cb, guard);
        }
    }
    return mapValues(o as object, rec) as RecMap<U>;
}

/**
 * Merges two objects where each leaf is an array. The resulting object has all
 * leafs concatenated if they are at the same path. If a leaf is only present
 * for one object, but not the other, it is left unchanged. Note, that both maps
 * must share their structure: If two paths are present both in `org` and `src`,
 * they must be of equal type.
 * @param org Array map one
 * @param src Array map two
 * @returns Array map with concatenated leafs
 */
export function mergeArrayMap<T>(org: RecMap<T[]>, src: RecMap<T[]>): RecMap<T[]> {
    function rec(l: RecMap<T[]>, r: RecMap<T[]>): RecMap<T[]> {
        if (isArray(l) && isArray(r)) {
            return l.concat(r);
        } else if (isObject(l) && isObject(r)) {
            return mergeWith(l, r, mergeArrayMap);
        } else if (Boolean(l) != Boolean(r)) {
            return l || r;
        } else {
            throw new TypeError();
        }
    }
    return rec(org, src);
}
