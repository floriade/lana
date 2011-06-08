-- bpfc, a tiny BPF compiler
-- Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
-- Swiss federal institute of technology (ETH Zurich)
-- Subject to the GPL.

import Char

type Parser sym res = [sym] -> [(res, [sym])]

spot :: (x -> Bool) -> Parser x x
spot f [] = []
spot f (x:xs)
    | f x = [(x, xs)]
    | otherwise = []

dig :: Parser Char Char
dig x = (spot isDigit) x

digit :: Parser Char Int
digit = spot isDigit <@ f
    where f a = ord a - ord '0'

sym :: Char -> Parser Char Char
sym s x = (spot (== s)) x

fin :: y -> Parser x y
fin x y = [(x, y)]

many :: Parser x y -> Parser x [y]
many p = (p <*> many p <@ list) <|> (fin [])
    where list (x, xs) = x:xs

option :: Parser x y -> Parser x [y]
option p x  = ((p <@ (:[])) <|> (fin [])) x

infixr 4 <|>
(<|>) :: Parser x y -> Parser x y -> Parser x y
(p1 <|> p2) x = (p1 x) ++ (p2 x)

infixr 6 <*>
(<*>) :: Parser x y -> Parser x z -> Parser x (y, z)
(p1 <*> p2) x = [ ((x1, x2), xs2)
                | (x1, xs1) <- p1 x
                , (x2, xs2) <- p2 xs1
                ]

infixr 5 <@
(<@) :: Parser x y -> (y -> z) -> Parser x z
(p <@ f) x  = [ (f x, xs)
              | (x, xs) <- p x
              ]

parse x = (sym 'a' <*> sym 'b' <*> (sym 'c' <|> dig)) x

main = do
    prog <- getContents
    let x = parse prog
    print $ x

