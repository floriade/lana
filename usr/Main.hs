import Char

type Parser sym res = [sym] -> [(res, [sym])]

data Expr = Lit Int | Bin Op Expr Expr deriving (Eq, Show)

data Op = Add | Sub | Mul | Div | Mod deriving (Eq, Show)

spot :: (x -> Bool) -> Parser x x
spot f [] = []
spot f (x:xs)
    | f x = [(x, xs)]
    | otherwise = []

dig :: Parser Char Char
dig x = (spot isDigit) x

sym :: Char -> Parser Char Char
sym s x = (spot (== s)) x

fin :: y -> Parser x y
fin x y = [(x, y)]

white :: Parser Char [Char]
white = ((many (spot (== '\t')))
    <|>  (many (spot (== ' ')))
    <|>  (many (spot (== '\n')))
    <|>  (many (spot (== '\r'))))

many :: Parser x y -> Parser x [y]
many p = (p <*> many p <@ list) <|> (fin [])
    where list (x, xs) = x:xs

many1 :: Parser x y -> Parser x [y]
many1 p = p <*> many p <@ list
    where list (x, xs) = x:xs

option :: Parser x y -> Parser x [y]
option p x = ((p <@ (:[])) <|> (fin [])) x

infixr 4 <|>
(<|>) :: Parser x y -> Parser x y -> Parser x y
(p1 <|> p2) x = (p1 x) ++ (p2 x)

infixr 6 <*>
(<*>) :: Parser x y -> Parser x z -> Parser x (y, z)
(p1 <*> p2) x = [ ((x1, x2), xs2)
                | (x1, xs1) <- p1 x
                , (x2, xs2) <- p2 xs1
                ]

infixr 6 <->
(<->) :: Parser x y -> Parser x z -> Parser x z
(p1 <-> p2) x = [ (x2, xs2)
                | (x1, xs1) <- p1 x
                , (x2, xs2) <- p2 xs1
                ]

infixr 5 <@
(<@) :: Parser x y -> (y -> z) -> Parser x z
(p <@ f) x  = [ (f x, xs)
              | (x, xs) <- p x
              ]

isOp :: Char -> Bool
isOp o = (o == '+') || (o == '-') || (o == '*') || (o =='/') || (o == '%')

parser :: Parser Char Expr
parser = litParser <|> opExprParser

litParser :: Parser Char Expr
litParser = (white <-> option (sym '-') <*> many1 (spot isDigit)) <@ charListToExpr.join 
    where join = uncurry (++)

opExprParser :: Parser Char Expr
opExprParser = (sym '(' <*> parser <*> (spot isOp) <*> parser <*> sym ')') <@ makeExpr
    where makeExpr :: (a, (Expr, (Char, (Expr, b)))) -> Expr
          makeExpr (_, (e1, (bop, (e2, _)))) = Bin (charToOp bop) e1 e2

charToOp :: Char -> Op
charToOp x = case x of
    '+' -> Add
    '-' -> Sub
    '*' -> Mul
    '/' -> Div
    '%' -> Mod

charListToExpr :: [Char] -> Expr
charListToExpr [] = Lit 0
charListToExpr (x:xs) = Lit (natural (x:xs))

natural :: [Char] -> Int
natural [] = 0
natural ('-':xs) = (-1) * natural xs 
natural (x:xs) = toDigit x * 10^(length xs) + natural xs

toDigit :: Char -> Int
toDigit x
    | isDigit x = ord x - ord '0'
    | otherwise = 0

topLevel :: Parser x y -> [x] -> y
topLevel p inp = case results of
    [] -> error "Syntax error!"
    _  -> head results
    where results = [found | (found,[]) <- p inp]

opValue :: Op -> Int -> Int -> Int
opValue Add x y = x + y
opValue Sub x y = x - y
opValue Mul x y = x * y
opValue Div x y = x `div` y
opValue Mod x y = x `mod` y

eval :: Expr -> Int
eval (Lit n) = n
eval (Bin op e1 e2) = (opValue op v1 v2)
    where 
    v1 = eval e1 
    v2 = eval e2 

doEval :: String -> String
doEval str = show (eval ((topLevel parser) str))

main = do
    prog <- getContents
    let x = doEval prog
    print $ prog
    print $ x

