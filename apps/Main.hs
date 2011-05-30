import Network
import Network.Socket
import Network.HTTP
import Network.HTTP.Stream
import System.IO
import Control.Monad
import Control.Arrow
import Control.Category
import Prelude hiding (id,(.))
import Text.XHtml.Transitional
import Control.Concurrent

getHogName = "Hog"
getHogVersion = "0.1.0"
getFullName = getHogName ++ " " ++ getHogVersion

data Family
    = AF_UNSPEC           -- unspecified
    | AF_LANA 
    deriving (Eq, Ord, Read, Show)

type RequestHandler = Request String -> IO (Response String)

--main = runHttpServer defaultIndexDoc
main = runHttpServer hellowWorldHandler

hellowWorldHandler :: RequestHandler
hellowWorldHandler _ =
    return $ successResponse $ prettyHtml helloWorldDoc

successResponse :: String -> Response String
successResponse  s =
    Response   (2,0,0) "" [] s

helloWorldDoc :: Html
helloWorldDoc =
    header << thetitle << (getFullName ++ " running!")
           Text.XHtml.Transitional.+++
               body << h1 << (getFullName ++ " running!")

--defaultIndexDoc :: Html
--defaultIndexDoc = hopReadFile "/var/www/index.html" >>= return . stringToHtml
--do
--    c <- hopReadFile "/var/www/index.html"
--    return $ stringToHtml liftM c

hopReadFile :: String -> IO String
hopReadFile filename = readFile filename

runHttpServer :: RequestHandler -> IO ()
runHttpServer r =
    withSocketsDo $ do
      sock <- socket AF_LANA Stream 0
      setSocketOption sock ReuseAddr 1
      bindSocket sock $ SockAddrInet 8080 iNADDR_ANY
      listen sock 8080
      forever $ acceptConnection sock $ handleHttpConnection r

acceptConnection :: Socket -> (Handle -> IO ()) -> IO ()
acceptConnection s k =
     Network.accept s >>= \(h,_,_) -> forkIO (k h) >> return ()

instance Stream Handle where
    readLine   h   = hGetLine h >>= \ l -> return $ Right (l ++ "\n")
    readBlock  h n = replicateM n (hGetChar h) >>= return . Right
    writeBlock h s = mapM_ (hPutChar h) s >>= return . Right
    close          = hClose

handleHttpConnection :: RequestHandler -> Handle -> IO ()
handleHttpConnection r c =
    runKleisli
    (receiveRequest >>> handleRequest r >>> handleResponse) c >>
    Network.HTTP.Stream.close c
    where
      receiveRequest  = Kleisli Network.HTTP.Stream.receiveHTTP
      handleRequest r = right (Kleisli r)
      handleResponse  = Kleisli (print ||| Network.HTTP.Stream.respondHTTP c)

