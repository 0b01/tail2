import { motion } from 'framer-motion';
import { url } from 'inspector';
import Image from "next/image";
import icon_img from "../../public/icon.png";

const Hello = () => {

    const headerVariants = {
        initial: {
            y: -100,
            opacity: 0
        },
        animate: {
            y: 0,
            opacity: 1,
            transition: {
                duration: 0.66,
                delay: 0
            }
        }
    };
    return (
        <motion.div
            className="my-10"
            variants={headerVariants}
            initial="initial"
            whileInView="animate"
            viewport={{ once: true }}
        >
            <div className="container mx-auto px-10">
                <div className="flex flex-col gap-10 text-center md:text-left md:flex-row items-center justify-between box-bg p-10">
                    <Image src={icon_img} width="196px" height="196px" className="rounded-full" />
                    <div>
                        <h3 className="header-color text-2xl md:text-4xl font-bold mt-5 mb-2">Join our community</h3>
                        <p className="text-color text-sm md:text-base">Join discord for announcement and discussions.</p>
                    </div>
                    <div>
                        {/* <button className="bg-main py-2 px-10 font-bold rounded-sm">Contact</button> */}
                        <DiscordButton url="https://discord.gg/krReQzBB8T"></DiscordButton>
                    </div>
                </div>
            </div>
        </motion.div>
    )
}

export default Hello;

interface IDiscordProps {url : string}

const DiscordButton = (props: IDiscordProps) => (
    <a
      href={props.url}
      style={{
        color: "white",
        fontWeight: "bold",
        borderRadius: 8,
        display: "inline-flex",
        alignItems: "center",
        padding: "10px 15px",
        backgroundColor: "#7289da",
        textDecoration: "none"
      }}
    >
      <div style={{ width: 25, height: 25, marginRight: 15 }}>
        <svg id="Layer_1" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 245 240">
          <path
            className="st0"
            d="M104.4 103.9c-5.7 0-10.2 5-10.2 11.1s4.6 11.1 10.2 11.1c5.7 0 10.2-5 10.2-11.1.1-6.1-4.5-11.1-10.2-11.1zM140.9 103.9c-5.7 0-10.2 5-10.2 11.1s4.6 11.1 10.2 11.1c5.7 0 10.2-5 10.2-11.1s-4.5-11.1-10.2-11.1z"
          />
          <path
            className="st0"
            d="M189.5 20h-134C44.2 20 35 29.2 35 40.6v135.2c0 11.4 9.2 20.6 20.5 20.6h113.4l-5.3-18.5 12.8 11.9 12.1 11.2 21.5 19V40.6c0-11.4-9.2-20.6-20.5-20.6zm-38.6 130.6s-3.6-4.3-6.6-8.1c13.1-3.7 18.1-11.9 18.1-11.9-4.1 2.7-8 4.6-11.5 5.9-5 2.1-9.8 3.5-14.5 4.3-9.6 1.8-18.4 1.3-25.9-.1-5.7-1.1-10.6-2.7-14.7-4.3-2.3-.9-4.8-2-7.3-3.4-.3-.2-.6-.3-.9-.5-.2-.1-.3-.2-.4-.3-1.8-1-2.8-1.7-2.8-1.7s4.8 8 17.5 11.8c-3 3.8-6.7 8.3-6.7 8.3-22.1-.7-30.5-15.2-30.5-15.2 0-32.2 14.4-58.3 14.4-58.3 14.4-10.8 28.1-10.5 28.1-10.5l1 1.2c-18 5.2-26.3 13.1-26.3 13.1s2.2-1.2 5.9-2.9c10.7-4.7 19.2-6 22.7-6.3.6-.1 1.1-.2 1.7-.2 6.1-.8 13-1 20.2-.2 9.5 1.1 19.7 3.9 30.1 9.6 0 0-7.9-7.5-24.9-12.7l1.4-1.6s13.7-.3 28.1 10.5c0 0 14.4 26.1 14.4 58.3 0 0-8.5 14.5-30.6 15.2z"
          />
        </svg>
      </div>
      <span>{"Join the Discord"}</span>
    </a>
  );