import { AiFillFacebook, AiFillInstagram, AiFillLinkedin, AiFillTwitterCircle } from "react-icons/ai";
import Image from "next/image";
import icon_img from "../../public/icon.png";

const Footer = () => {
    return (
        <section className="py-10">
            <div className="container mx-auto px-10">
                <div className="grid lg:grid-cols-4 md:grid-cols-2 gap-5">
                    <div>
                        <p className="text-color text-sm">
                            <Image src={icon_img} width="196px" height="196px" className="rounded-full" />
                        </p>
                    </div>
                    {/* <div>
                        <h3 className="header-color text-lg font-bold">Products</h3>
                        <ul>
                            <li className="text-color cursor-pointer text-sm my-2">Contact US</li>
                        </ul>
                    </div>
                    <div>
                        <h3 className="header-color text-lg font-bold">Company</h3>
                        <ul>
                            <li className="text-color cursor-pointer text-sm my-2">Consectetur adipiscing</li>
                        </ul>
                    </div>
                    <div>
                        <h3 className="header-color text-lg font-bold">Products</h3>
                        <ul>
                            <li className="text-color cursor-pointer text-sm my-2">Nostrud exercitation</li>
                        </ul>
                    </div> */}
                </div>
                <div className="flex justify-between items-center my-5">
                        
                    <p className="text-color">Made with ❤️ in Seattle </p>
                    {/* | © tail2. All rights reserved. */}
                    <div className="flex items-center gap-5">
                        {/* <AiFillTwitterCircle className="text-color cursor-pointer" /> */}
                        {/* <AiFillFacebook className="text-color cursor-pointer" /> */}
                        {/* <AiFillInstagram className="text-color cursor-pointer" /> */}
                        {/* <AiFillLinkedin className="text-color cursor-pointer" /> */}
                    </div>
                </div>
            </div>
        </section>
    )
}

export default Footer;