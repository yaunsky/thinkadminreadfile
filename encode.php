<?php
$name="../../../etc/passwd";
for($i=0;$i<strlen($ename=iconv('UTF-8','GBK//TRANSLIT',$name));$i++)
{
  echo str_pad(base_convert(ord($ename[$i]),10,36),2,0,0);
}
?>