<?php

define("NONSENSE_BYTE_OFFSET", 9);


class DBPFfile
{

    var $majorVersion;
    var $minorVersion;
    var $reserved;
    var $dateCreated;
    var $dateModified;
    var $indexMajorVersion;
    var $indexMinorVersion;
    var $indexCount;
    var $indexOffset;
    var $indexSize;
    var $holesCount;
    var $holesOffset;
    var $holesSize;
    var $reserved2;
    var $indexData;

    // ** Internally used I/O functions
    // Reads a 4 byte unsigned integer

    /*
    Used internally by the class to read a C/C++
    "unsigned long" (a 4 byte unsigned integer)
    from an open file
    $fh - the file handle from which to read
    returns - returns the value read; has no error return
    */
    function read_UL4($fh)
    {
        $d = fread($fh, 4);
        $a = unpack("Vn", $d);
        return $a["n"];
    }

    // Reads a 2 byte unsigned integer

    /*
    Used internally by the class to read a C/C++
    "unsigned short" (a 2 byte unsigned integer)
    from an open file
    $fh - the file handle from which to read
    returns - returns the value read; has no error return
    */
    function read_UL2($fh)
    {
        $d = fread($fh, 2);
        $a = unpack("vn", $d);
        return $a["n"];
    }

    // Reads a 1 byte unsigned integer

    /*
    Used internally by the class to read a C/C++
    "unsigned char" (a 1 byte unsigned integer)
    from an open file
    $fh - the file handle from which to read
    returns - returns the value read; has no error return
    */
    function read_UL1($fh)
    {
        $d = fread($fh, 1);
        $a = unpack("Cn", $d);
        return $a["n"];
    }

    // Reads a Unicode string of specified length

    /*
    Used internally by the class to read a C/C++
    array of "wchar_t" (a 2 byte character)
    from an open file
    $fh - the file handle from which to read
    $len - the number of characters to read
    returns - returns the value read; has no error return
    */
    function read_unistr($fh, $len)
    {
        $s = "";
        for ($i = 0; $i < $len; ++$i) {
            $c = fread($fh, 1);
            if (ord($c) != 0) $s.= $c;
            fseek($fh, 1, SEEK_CUR);
        }

        return $s;
    }

    function read_nullstring($fh)
    {
        $s = "";
        $str = fread($fh, 1);
        while (ord($str) != 0) {
            $s.= $str;
            $str = fread($fh, 1);
        }

        return $s;
    }

    // Reads a string length and then the string

    /*
    Used internally by the class to read a 4 byte unsigned integer
    and then read a string that many characters in length
    $fh - the file handle from which to read
    returns - returns the string read (not the length read); has no error return
    */
    function read_lenstr($fh)
    {
        $str_length = $this->read_UL4($fh);
        $s = fread($fh, $str_length);
        return $s;
    }

    // Reads a string length and then the Unicode string

    /*
    Used internally by the class to read a 4 byte unsigned integer
    and then read a Unicode string that many characters in length
    $fh - the file handle from which to read
    returns - returns the Unicode string read (not the length read); has no error return
    */
    function read_lenwstr($fh)
    {
        $str_length = $this->read_UL4($fh);
        $s = $this->read_unistr($fh, $str_length);
        return $s;
    }

    function strhex($string)
    {
        $hex = "";
        for ($i = 0; $i < strlen($string); $i++) $hex.= (strlen(dechex(ord($string[$i]))) < 2) ? "0" . dechex(ord($string[$i])) : dechex(ord($string[$i]));
        return $hex;
    }

    function hexstr($hex)
    {
        $string = "";
        for ($i = 0; $i < strlen($hex) - 1; $i+= 2) $string.= chr(hexdec($hex[$i] . $hex[$i + 1]));
        return $string;
    }

    // Reads a string and reverses it, taking into account hex groupings:

    /*
    for example, 2397586c becomes 6c589723
    */
    function revhex($string)
    {
        $revstring = "";

        for ($i = 0; $i < strlen($string) - 1; $i+= 2) {
            $revstring = $string[$i] . $string[$i + 1] . $revstring;
        }

        return $revstring;
    }

    // Decompression function used on string

    /*
    PHP DBPF decompression by Delphy
    Thanks to dmchess (http://hullabaloo.simshost.com/forum/viewtopic.php?t=6578&postdays=0&postorder=asc)
    for the Perl code that was used for this.
    $handle - file handle for reading
    $len - length of compressed string
    */
    function decompress($handle, $len) {
               $buf = "";
               $answer = "";
               $answerlen = 0;
               $numplain = "";
               $numcopy = "";
               $offset = "";
       
       // Main loop:
               for (;$len>0;) {
                       $cc = $this->read_UL1($handle);
                       $len -= 1;
               //      printf("      Control char is %02x, len remaining is %08x. \n",$cc,$len);
                       if ($cc >= 252): // 0xFC
                               $numplain = $cc & 0x03;
                               if ($numplain > $len) { $numplain = $len; }
                               $numcopy = 0;
                               $offset = 0;
                       elseif ($cc >= 224): // 0xE0
                               $numplain = ($cc - 0xdf) << 2;
                               $numcopy = 0;
                               $offset = 0;
                       elseif ($cc >= 192): // 0xC0
                               $len -= 3;
                               $byte1 = $this->read_UL1($handle);
                               $byte2 = $this->read_UL1($handle);
                               $byte3 = $this->read_UL1($handle);
                               $numplain = $cc & 0x03;
                               $numcopy = (($cc & 0x0c) <<6) + 5 + $byte3;
                               $offset = (($cc & 0x10) << 12 ) + ($byte1 << 8) + $byte2;
                       elseif ($cc >= 128): // 0x80
                               $len -= 2;
                               $byte1 = $this->read_UL1($handle);
                               $byte2 = $this->read_UL1($handle);
                               $numplain = ($byte1 & 0xc0) >> 6;
                               $numcopy = ($cc & 0x3f) + 4;
                               $offset = (($byte1 & 0x3f) << 8) + $byte2;
                       else:
                               $len -= 1;
                               $byte1 = $this->read_UL1($handle);
                               $numplain = ($cc & 0x03);
                               $numcopy = (($cc & 0x1c) >> 2) + 3;
                               $offset = (($cc & 0x60) << 3) + $byte1;
                       endif;
                       $len -= $numplain;

               // This section basically copies the parts of the string to the end of the buffer:
                       if ($numplain > 0) {
                               $buf = fread($handle, $numplain);
                               $answer = $answer.$buf;
                       }
                       $fromoffset = strlen($answer) - ($offset + 1);  # 0 == last char
                       for ($i=0;$i<$numcopy;$i++) {
                               $answer = $answer.substr($answer,$fromoffset+$i,1);
                       }
                       $answerlen += $numplain;
                       $answerlen += $numcopy;
               }

               // Return the decompressed string back:
               return $answer;
       }


    // Loads a DBPF file

    /*
    $fileName - the name of a file to open
    returns - true on success, a string value on error (use $ret === true to test for success or failure)
    */
    function loadFile($handle, $offset = 0)
    {

        $ret = "";

        //                $this->m_fileName = $fileName;
        //                $handle = fopen($fileName, "rwb");

        if ($handle) {
            $start = $offset;
            if ($offset > 0) {
                fseek($handle, $offset);
            }

            $test = fread($handle, 4); // Should be DBPF
            if ($test != "DBPF") {
                echo $test . " - This is not a DBPF file!";
                return;
            }

            $this->majorVersion = $this->read_UL4($handle);
            $this->minorVersion = $this->read_UL4($handle);
            $this->reserved = fread($handle, 12);
            $this->dateCreated = $this->read_UL4($handle);
            $this->dateModified = $this->read_UL4($handle);
            $this->indexMajorVersion = $this->read_UL4($handle);
            $this->indexCount = $this->read_UL4($handle);
            $this->indexOffset = $this->read_UL4($handle);
            $this->indexSize = $this->read_UL4($handle);
            $this->holesCount = $this->read_UL4($handle);
            $this->holesOffset = $this->read_UL4($handle);
            $this->holesSize = $this->read_UL4($handle);
            $this->indexMinorVersion = $this->read_UL4($handle) - 1;
            $this->reserved2 = fread($handle, 32);
            $headerEnd = ftell($handle);

            // Seek to index

            fseek($handle, $offset + $this->indexOffset);

            //  echo ftell($handle)."\n";

            for ($i = 0; $i < $this->indexCount; $i++) {
                $this->indexData[$i]['typeID'] = $this->revhex($this->strhex(fread($handle, 4)));
                $this->indexData[$i]['groupID'] = $this->revhex($this->strhex(fread($handle, 4)));
                $this->indexData[$i]['instanceID'] = $this->revhex($this->strhex(fread($handle, 4)));
                if (($this->indexMajorVersion == "7") && ($this->indexMinorVersion == "1")) {
                    $this->indexData[$i]['instanceID2'] = $this->revhex($this->strhex(fread($handle, 4)));
                }

                $this->indexData[$i]['offset'] = $this->read_UL4($handle);
                $this->indexData[$i]['filesize'] = $this->read_UL4($handle);
                $this->indexData[$i]['compressed'] = false;
                $this->indexData[$i]['truesize'] = 0;
            }

            // echo print_r($indexData, true)."\n";
            // First check for a DIR resource

            foreach($this->indexData as $value) {
                if ($value['typeID'] == 'e86b1eef') {

                    // echo "Getting DIR resource of size ".$value['filesize']."... <br />";

                    fseek($handle, $offset + $value['offset']);

                    // Each record in a Sims 2 file is 20 bytes long, so to get the total number of records we
                    // divide $value['filsize'] by 20.

                    if (($this->indexMajorVersion == "7") && ($this->indexMinorVersion == "1")) {
                        $numRecords = ($value['filesize'] / 20);
                    }
                    else {
                        $numRecords = ($value['filesize'] / 16);
                    }

                    for ($i = 0; $i < $numRecords; $i++) {
                        $typeID = $this->revhex($this->strhex(fread($handle, 4)));
                        $groupID = $this->revhex($this->strhex(fread($handle, 4)));
                        $instanceID = $this->revhex($this->strhex(fread($handle, 4)));
                        if (($this->indexMajorVersion == "7") && ($this->indexMinorVersion == "1")) {
                            $instanceID2 = $this->revhex($this->strhex(fread($handle, 4)));
                        }

                        $filesize_nc = $this->read_UL4($handle);
                        for ($j = 0; $j < $this->indexCount; $j++) {
                            if ($this->indexData[$j]['typeID'] == $typeID) {
                                if ($this->indexData[$j]['groupID'] == $groupID) {
                                    if ($this->indexData[$j]['instanceID'] == $instanceID) {
                                        if (($this->indexMajorVersion == "7") && ($this->indexMinorVersion == "1")) {
                                            if ($this->indexData[$j]['instanceID2'] == $instanceID2) {
                                                $this->indexData[$j]['compressed'] = true;
                                                $this->indexData[$j]['truesize'] = $filesize_nc;
                                            }
                                        }
                                        else {
                                            $this->indexData[$j]['compressed'] = true;
                                            $this->indexData[$j]['truesize'] = $filesize_nc;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            foreach($this->indexData as $value) {
                /* Catalog Description - CTSS */
                if ($value['typeID'] == '43545353') {

                    // echo "Grabbing CTSS file at offset ".$value['offset']." (".($offset + $value['offset']).")...<br />";

                    fseek($handle, $offset + $value['offset']);
                    fread($handle, 64);
                    fread($handle, 2); // FormatCode
                    $numStrings = $this->read_UL2($handle);

                    // echo "NumStrings: ".$numStrings."<br />";

                    $numStrings = 2;
                    for ($j = 0; $j < $numStrings; $j++) {
                        $stringPairs = $this->read_UL1($handle);

                        // echo "NumStringPairs: ".$stringPairs."<br />";
                        // for ($i = 0; $i < $stringPairs; $i++)
                        // {

                        $ret.= $this->read_nullstring($handle);
                        if ($j == 0) {
                            $ret.= "<br />";
                        }

                        echo "..." . $ret . " - ";
                        $ret2 = $this->read_nullstring($handle);

                        // echo $ret2."<br />";
                        // }

                    }
                }

                /* Object XML */
                if ($value['typeID'] == 'cca8e925') {
                    if ($value['compressed'] == true) {
                        fseek($handle, $offset + $value['offset']);
                        $dword = $this->read_UL4($handle);

                        // $dword = fread($handle, 4);

                        $data = fread($handle, 5);

                        // echo $dword."<br /> \n ";
                        // echo $data."<br /> \n ";
                        // echo "decompressing file... <br />";

                        $xmldata = $this->decompress($handle, $dword - 9);
                        $objXML = new xml2Array();
                        $arrOutput2 = $objXML->parse($xmldata);
                        foreach($arrOutput2[CGZPROPERTYSETSTRING][ANYSTRING] as $value) {
                            if ($value[KEY] == 'description') {
                                $ret = $value[DATA];
                                echo "-- " . $value[DATA] . "<br />";
                            }
                        }
                    }
                }
            }

            if ($ret == '') {
                foreach($this->indexData as $value) {
                    /* String Text Lists - STR# */
                    if ($value['typeID'] == '53545223') {
                        echo "Grabbing STR# file at offset " . $value['offset'] . " (" . ($offset + $value['offset']) . ")...\n";
                        fseek($handle, $offset + $value['offset']);
                        if ($value['compressed'] == true) {
                            fseek($handle, $offset + $value['offset']);
                            $dword = $this->read_UL4($handle);

                            // $dword = fread($handle, 4);

                            $data = fread($handle, 5);

                            // echo $dword."<br /> \n ";
                            // echo $data."<br /> \n ";
                            // echo "decompressing file... <br />";

                            $data = $this->decompress($handle, $dword - 9);

                            // $data now contains the decompressed data so we have to get the string pairs from it
                            // echo strlen($data)."\n";
                            // if (strlen($data) > 66) {
                            // First, chop off the filename of 64 bytes

                            $data = substr($data, 64);

                            // }
                            // Next, the FormatCode (2 bytes)

                            $data = substr($data, 2);

                            // echo $data."\n";

                            $numStrings = unpack("vn", substr($data, 0, 2));

                            // echo "NumStrings: ".$numStrings."\n";

                            $numStrings = 2;
                            $soffset = 2;
                            for ($j = 0; $j < $numStrings; $j++) {
                                if ($soffset < strlen($data)) {
                                    $languageCode = unpack("Cn", substr($data, $soffset, 1));
                                    $soffset++;

                                    // Grab string pair

                                    for ($l = 0; $l < 2; $l++) {
                                        $k = 0;
                                        for (; $k < 1;) {
                                            $tempstring = substr($data, $soffset, 1);
                                            if (ord($tempstring) != 0) {
                                                $ret.= $tempstring;
                                            }
                                            else {
                                                $k = 1;
                                            }

                                            $soffset++;
                                        }
                                    }

                                    // $ret .= $this->read_nullstring ($handle);

                                    if ($j == 0) {
                                        $ret.= "<br />";
                                    }

                                    echo "..." . $ret . " - ";

                                    // $ret2 = $this->read_nullstring($handle);
                                    // echo $ret2."<br />";

                                }
                            }
                        }
                        else {
                            fseek($handle, $offset + $value['offset']);
                            fread($handle, 64);
                            fread($handle, 2); // FormatCode
                            $numStrings = $this->read_UL2($handle);

                            // echo "NumStrings: ".$numStrings."<br />";

                            $numStrings = 2;
                            for ($j = 0; $j < $numStrings; $j++) {
                                $languageCode = $this->read_UL1($handle);
                                $ret.= $this->read_nullstring($handle);
                                if ($j == 0) {
                                    $ret.= "<br />";
                                }

                                echo "..." . $ret . " - ";
                                $ret2 = $this->read_nullstring($handle);

                                // echo $ret2."<br />";

                            }
                        }
                    }
                }
            }

            return $ret;
        }
        else {
            return "Could not open file '" . $fileName . "'";
        }
    }
}

?>